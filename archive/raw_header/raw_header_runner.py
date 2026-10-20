# Sanitized historical reference: source-specific evidence and live configuration are not distributed.
#!/usr/bin/env python3
'Raw-header adapter for the shared source-preserving Gmail migration engine.\n\nOnly one immutable source fingerprint receives the audited multipart-header\nrepair. The shared engine retains account, checkpoint, source, and readback\ncontrols. SG_PILOT_LIMIT optionally stops before the next import after N\nverified import_one outcomes in this process; unset it to resume normally.\n'

from __future__ import annotations

import base64
import functools
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import sys
from typing import Any, Callable


ENGINE_PATH = next(p / "gmail_eml_migration_v2.py" for p in Path(__file__).resolve().parents if (p / "gmail_eml_migration_v2.py").is_file())
AUDITED_SOURCE_SHA256 = '000000000000000000000000000000000000000000000000000000000000d36f'
AUDITED_PREPARED_SHA256 = '000000000000000000000000000000000000000000000000000000000000fd0c'
REPAIR_NAME = "sg_exact_sha256_multipart_container_cte_removal_v1"
AUDITED_RANGES = ((1199, 1244), (2859, 2904))
AUDITED_HEADER = b"Content-Transfer-Encoding: quoted-printable\r\n"
AUDITED_DEFECTS = ["InvalidMultipartContentTransferEncodingDefect"] * 2

_spec = importlib.util.spec_from_file_location("_sg_shared_migration_engine", ENGINE_PATH)
if _spec is None or _spec.loader is None:
    raise RuntimeError("Cannot load the shared migration engine.")
engine = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = engine
_spec.loader.exec_module(engine)
_original_prepare_source_bytes = engine.prepare_source_bytes
_original_import_one = engine.import_one
_original_readback_message = engine.readback_message
_original_save_state = engine.save_state

PRIMARY_HEADERS = ("From", "To", "Cc", "Subject", "Message-ID", "Date")
RAW_FALLBACK_ISSUES = frozenset(
    f"readback {header} header differs from the source"
    for header in ("From", "To", "Cc", "Subject")
)


def save_state(profile: Any, checkpoint: dict[str, Any], item_key: str, **updates: Any) -> None:
    'Keep Raw-header transport ambiguity evidence readable by the shared loader.\n\n    HTTP status zero is deliberately preserved. Copy only an actually recorded\n    transport error, retaining its fingerprint and uncertain outcome; this does\n    not select a Gmail candidate or authorize a retry.\n    '
    if profile.destination == profile.source_mailbox == 'example-a88c3515@example.org':
        merged = {**checkpoint["states"][item_key], **updates}
        recognized = any(merged.get(field) for field in (
            "error", "error_type", "reconciliation_observations", "http_status"
        ))
        google_error = merged.get("google_error")
        if (
            merged.get("status") == "uncertain"
            and merged.get("google_error_fingerprint")
            and not recognized
            and isinstance(google_error, str)
            and google_error.strip()
        ):
            updates = {**updates, "error": google_error}
    _original_save_state(profile, checkpoint, item_key, **updates)


def primary_raw_headers(message: Any) -> dict[str, list[str]]:
    return {
        name: [str(value) for key, value in message.raw_items() if key.casefold() == name.casefold()]
        for name in PRIMARY_HEADERS
    }


def mime_tree_inventory(message: Any) -> list[dict[str, Any]]:
    """Fingerprint an ordered MIME tree, including attached-message headers.

    Additional top-level transport headers are irrelevant to this inventory.
    Nested headers, MIME headers, multipart framing text, and decoded leaf
    content remain protected. Transfer encoding may differ only when decoded
    bytes match; no message/rfc822 nested header is silently omitted.
    """
    entries: list[dict[str, Any]] = []

    def text_fingerprint(value: str | None) -> dict[str, Any] | None:
        if value is None:
            return None
        raw = value.encode("utf-8", "surrogateescape")
        return {"size_bytes": len(raw), "sha256": engine.sha256_bytes(raw)}

    def visit(part: Any, path: tuple[int, ...]) -> None:
        protected_headers = [
            (name.casefold(), str(value))
            for name, value in part.raw_items()
            if name.casefold() != "content-transfer-encoding"
            and (path or name.casefold().startswith("content-") or name.casefold() == "mime-version")
        ]
        payload = part.get_payload()
        children = payload if isinstance(payload, list) else None
        entry = {
            "path": list(path),
            "content_type": part.get_content_type(),
            "content_disposition": part.get_content_disposition(),
            "filename": part.get_filename(),
            "content_id": str(part.get("Content-ID", "")).strip(),
            "charset": part.get_content_charset(),
            "protected_header_count": len(protected_headers),
            "protected_headers_sha256": engine.sha256_bytes(engine.canonical_json_bytes(protected_headers)),
            "child_count": len(children) if children is not None else 0,
            "preamble": text_fingerprint(part.preamble),
            "epilogue": text_fingerprint(part.epilogue),
        }
        if children is None:
            decoded = part.get_payload(decode=True)
            if not isinstance(decoded, bytes):
                raise engine.MigrationError("Raw-header fallback found an undecodable MIME leaf.")
            entry["decoded_size_bytes"] = len(decoded)
            entry["decoded_sha256"] = engine.sha256_bytes(decoded)
        entries.append(entry)
        for index, child in enumerate(children or []):
            visit(child, path + (index,))

    visit(message, ())
    if engine.collect_defects(message):
        raise engine.MigrationError("Raw-header fallback found MIME or transfer-decoding defects.")
    return entries


def install_run_readback(profile: Any, manifest: dict[str, Any]) -> None:
    'Install a read-only, exact-receipt fallback only for this Raw-header run.'
    expected_mailbox = 'example-a88c3515@example.org'
    if (
        profile.destination != expected_mailbox
        or profile.source_mailbox != expected_mailbox
        or manifest.get("source_mailbox") != expected_mailbox
        or manifest.get("expected_destination") != expected_mailbox
    ):
        raise engine.MigrationError('Raw-header fallback is restricted to the Raw-header mailbox.')
    rows = engine.row_by_key(manifest)

    def readback_message(service: Any, gmail_id: str) -> dict[str, Any]:
        metadata = _original_readback_message(service, gmail_id)
        checkpoint = engine.load_checkpoint(profile, manifest, create=False)
        owners = [
            key for key, state in checkpoint["states"].items()
            if str(state.get("gmail_message_id", "")) == gmail_id
        ]
        if len(owners) != 1 or owners[0] not in rows:
            return metadata
        item_key = owners[0]
        row, state = rows[item_key], checkpoint["states"][item_key]
        expected_labels = engine.expected_label_ids_for_row(row, checkpoint.get("gmail_labels", {}))
        metadata_issues = engine.verify_readback_payload(row, gmail_id, metadata, expected_labels)
        if not metadata_issues or not set(metadata_issues).issubset(RAW_FALLBACK_ISSUES):
            return metadata

        prepared, observed = engine.source_bytes_for_state(profile, row, state)
        if (
            observed.get("source_sha256") != row["source_sha256"]
            or observed.get("prepared_sha256") != row["prepared_sha256"]
            or engine.sha256_bytes(prepared) != row["prepared_sha256"]
        ):
            raise engine.MigrationError("Raw-header fallback source fingerprint differs from the manifest.")
        expected_message = engine.BytesParser(policy=engine.policy.default).parsebytes(prepared)
        source_mime = mime_tree_inventory(expected_message)
        try:
            response = engine.execute_idempotent(
                lambda: service.users().messages().get(
                    userId="me", id=gmail_id, format="raw",
                    fields="id,threadId,labelIds,internalDate,raw",
                )
            )
        except Exception as exc:
            engine.raise_if_google_access_block(exc, "reading exact Gmail raw content")
            raise engine.MigrationError("Exact Gmail raw readback failed; no message was retried.") from exc
        encoded = response.get("raw")
        if response.get("id") != gmail_id or not isinstance(encoded, str):
            return metadata
        try:
            remote_raw = base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
        except (ValueError, TypeError):
            return metadata
        remote_message = engine.BytesParser(policy=engine.policy.default).parsebytes(remote_raw)
        primary_headers_equal = primary_raw_headers(expected_message) == primary_raw_headers(remote_message)
        gmail_mime = mime_tree_inventory(remote_message)
        mime_equal = source_mime == gmail_mime
        raw_payload = {
            **{key: value for key, value in response.items() if key != "raw"},
            "payload": {"headers": [
                {"name": name, "value": str(value)}
                for name, value in remote_message.items()
            ]},
        }
        raw_issues = engine.verify_readback_payload(row, gmail_id, raw_payload, expected_labels)
        if not primary_headers_equal or not mime_equal or raw_issues:
            return metadata
        final_prepared, final_observed = engine.source_bytes_for_state(profile, row, state)
        if (
            engine.sha256_bytes(final_prepared) != row["prepared_sha256"]
            or final_observed.get("source_sha256") != row["source_sha256"]
            or final_observed.get("prepared_sha256") != row["prepared_sha256"]
        ):
            raise engine.MigrationError("Raw-header fallback source changed during verification.")
        if not re.fullmatch(r"[0-9a-f]{64}", item_key):
            raise engine.MigrationError("Raw-header fallback item key is invalid.")
        evidence = {
            "schema_version": 1,
            "checked_at": engine.utc_now(),
            "passed": True,
            "destination": expected_mailbox,
            "item_key": item_key,
            "relative_path": row["relative_path"],
            "gmail_message_id": gmail_id,
            "source_sha256": row["source_sha256"],
            "prepared_sha256": row["prepared_sha256"],
            "gmail_raw_sha256": engine.sha256_bytes(remote_raw),
            "original_metadata_issues": metadata_issues,
            "original_metadata_payload": metadata,
            "raw_readback_payload": raw_payload,
            "primary_headers_equal": True,
            "source_primary_raw_headers": primary_raw_headers(expected_message),
            "gmail_primary_raw_headers": primary_raw_headers(remote_message),
            "mime_equal": True,
            "source_mime": source_mime,
            "gmail_mime": gmail_mime,
            "source_files_unchanged": True,
            "expected_label_ids": expected_labels,
            "raw_readback_issues": [],
            "validation_scope": "Exact saved receipt; primary raw header instances; full ordered MIME tree, nested headers and decoded leaves; engine ID, Message-ID, Date, internalDate and expected labels",
        }
        evidence_path = profile.state_dir / "raw-header-verifications" / f"{item_key}.json"
        engine.write_json_atomic(evidence_path, evidence)
        return raw_payload

    engine.readback_message = readback_message


def prepare_source_bytes(raw: bytes) -> tuple[bytes, list[str], dict[str, int], list[str]]:
    if hashlib.sha256(raw).hexdigest() != AUDITED_SOURCE_SHA256:
        return _original_prepare_source_bytes(raw)

    original = engine.BytesParser(policy=engine.policy.default).parsebytes(raw)
    original_defects = engine.collect_defects(original)
    if original_defects != AUDITED_DEFECTS:
        raise engine.MigrationError('Audited Raw-header source parser defects changed.')
    prepared = raw
    for start, end in reversed(AUDITED_RANGES):
        if raw[start:end] != AUDITED_HEADER:
            raise engine.MigrationError('Audited Raw-header container header bytes changed.')
        prepared = prepared[:start] + prepared[end:]
    if hashlib.sha256(prepared).hexdigest() != AUDITED_PREPARED_SHA256:
        raise engine.MigrationError('Audited Raw-header prepared fingerprint mismatch.')
    parsed = engine.BytesParser(policy=engine.policy.default).parsebytes(prepared)
    if engine.collect_defects(parsed) or sum(1 for _ in parsed.walk()) != 4:
        raise engine.MigrationError('Audited Raw-header prepared MIME validation failed.')
    return prepared, [REPAIR_NAME], {REPAIR_NAME: 2}, original_defects


def make_pilot_importer(original: Callable[..., str], limit: int) -> Callable[..., str]:
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
        raise engine.MigrationError("SG_PILOT_LIMIT must be a nonnegative integer.")
    verified = 0

    @functools.wraps(original)
    def import_one(*args: Any, **kwargs: Any) -> str:
        nonlocal verified
        if verified >= limit:
            raise engine.MigrationError("Pilot complete; resume same checkpoint")
        outcome = original(*args, **kwargs)
        if outcome == "verified":
            verified += 1
        return outcome

    return import_one


engine.prepare_source_bytes = prepare_source_bytes
engine.save_state = save_state


def main(argv: list[str] | None = None) -> int:
    pilot_value = os.environ.get("SG_PILOT_LIMIT")
    engine.import_one = _original_import_one
    engine.readback_message = _original_readback_message
    if pilot_value is not None:
        if not re.fullmatch(r"[0-9]+", pilot_value):
            print("STOPPED: SG_PILOT_LIMIT must be a nonnegative integer.", file=sys.stderr)
            return 2
        engine.import_one = make_pilot_importer(_original_import_one, int(pilot_value))
    effective_argv = list(argv) if argv is not None else sys.argv[1:]
    if effective_argv and effective_argv[0] == "run":
        args = engine.parse_args(effective_argv)
        try:
            profile = engine.load_profile(args.profile)
            manifest = engine.load_manifest(profile)
            install_run_readback(profile, manifest)
        except engine.MigrationError as exc:
            print(f"STOPPED: {exc}", file=sys.stderr)
            return 2
    return engine.main(argv)


if __name__ == "__main__":
    raise SystemExit("Archived reference variant. Use the configurable v2 engine at the repository root.")
    raise SystemExit(main())
