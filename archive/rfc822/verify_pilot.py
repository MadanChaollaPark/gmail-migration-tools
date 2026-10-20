# Sanitized historical reference: source-specific evidence and live configuration are not distributed.
#!/usr/bin/env python3
'Read-only Gmail fidelity check of exactly five checkpointed rfc822 pilot receipts.\n\nThe existing engine loads/refreshes the mailbox-bound credential. Gmail calls\nonly read the account profile and exact receipt IDs. No raw mail is written to\ndisk; only hashes, MIME descriptors, and validation results enter the report.\n'

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import sys

import runner


m = runner.engine
HERE = Path(__file__).resolve().parent
PROFILE = HERE / "profile.json"
REPORT = HERE / "pilot-content-verification.json"
EXPECTED_MAILBOX = 'example-49d20801@example.org'
EXPECTED_RECEIPTS = 5
MAX_RECEIPTS = 10


def mime_inventory(raw: bytes) -> dict:
    message = m.BytesParser(policy=m.policy.default).parsebytes(raw)
    parts = []

    def text_fingerprint(value: str | None) -> dict | None:
        if value is None:
            return None
        encoded = value.encode("utf-8", "surrogateescape")
        return {"size_bytes": len(encoded), "sha256": hashlib.sha256(encoded).hexdigest()}

    def visit(part, path: tuple[int, ...]) -> None:
        # Gmail may add top-level transport headers. All nested headers and all
        # top-level MIME headers are content evidence. Transfer encoding itself
        # may differ only when the decoded bytes remain exactly equal.
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
            "protected_headers_sha256": m.sha256_bytes(m.canonical_json_bytes(protected_headers)),
            "child_count": len(children) if children is not None else 0,
            "preamble": text_fingerprint(part.preamble),
            "epilogue": text_fingerprint(part.epilogue),
        }
        if children is None:
            decoded = part.get_payload(decode=True)
            if not isinstance(decoded, bytes):
                raise m.MigrationError("A leaf has no decodable byte payload.")
            entry["decoded_size_bytes"] = len(decoded)
            entry["decoded_sha256"] = hashlib.sha256(decoded).hexdigest()
        parts.append(entry)
        for index, child in enumerate(children or []):
            visit(child, path + (index,))

    visit(message, ())
    defects = m.collect_defects(message)
    if defects:
        raise m.MigrationError("MIME or transfer-decoding defects remain.")
    return {"parts": parts}


def inventory_issues(expected: dict, observed: dict) -> list[str]:
    issues = []
    missing = object()
    for key in ("parts",):
        if len(expected[key]) != len(observed[key]):
            issues.append(f"{key}_count_mismatch")
        for index, (before, after) in enumerate(zip(expected[key], observed[key])):
            for field in sorted(before.keys() | after.keys()):
                if before.get(field, missing) != after.get(field, missing):
                    issues.append(f"{key}[{index}].{field}_mismatch")
    return issues


def main() -> int:
    report = {
        "checked_at": m.utc_now(),
        "destination": EXPECTED_MAILBOX,
        "expected_receipts": EXPECTED_RECEIPTS,
        "max_receipts": MAX_RECEIPTS,
        "gmail_writes": 0,
        "additional_transport_headers_allowed": True,
        "content_validation_scope": "Ordered MIME paths, protected MIME and nested headers, preamble, epilogue, and decoded leaf hashes; primary headers, receipt ID, internalDate and expected labels also checked",
        "rows": [],
        "ok": False,
    }
    try:
        profile = m.load_profile(PROFILE)
        if profile.destination != EXPECTED_MAILBOX or profile.source_mailbox != EXPECTED_MAILBOX:
            raise m.MigrationError('The pilot verifier is restricted to the rfc822 mailbox.')
        immutable_paths = (PROFILE, profile.manifest_path, profile.checkpoint_path)
        original_hashes = {path: m.sha256_file(path) for path in immutable_paths}
        manifest = m.load_manifest(profile)
        checkpoint = m.load_checkpoint(profile, manifest, create=False)
        verified = [
            (row, checkpoint["states"][row["item_key"]])
            for row in manifest["messages"]
            if checkpoint["states"][row["item_key"]]["status"] == "verified"
        ]
        report["verified_receipt_count"] = len(verified)
        if len(verified) != EXPECTED_RECEIPTS or len(verified) > MAX_RECEIPTS:
            raise m.MigrationError("Verified receipt count differs from the bounded pilot.")
        if len({state["gmail_message_id"] for _, state in verified}) != len(verified):
            raise m.MigrationError("Pilot Gmail receipt IDs are not unique.")

        # Validate all local pilot bytes before obtaining credentials or reading Gmail.
        prepared_rows = []
        for row, state in verified:
            prepared, observed = m.source_bytes_for_state(profile, row, state)
            if m.sha256_bytes(prepared) != state["verified_prepared_sha256"]:
                raise m.MigrationError("Checkpoint receipt does not match prepared upload bytes.")
            prepared_rows.append((row, state, prepared, mime_inventory(prepared)))

        _, service, _ = m.load_authorized_credentials(profile)
        # load_authorized_credentials already performs this exact-account check.
        report["exact_account_guard_passed"] = True
        for row, state, prepared, expected_mime in prepared_rows:
            gmail_id = str(state["gmail_message_id"])
            response = m.execute_idempotent(
                lambda gmail_id=gmail_id: service.users().messages().get(
                    userId="me", id=gmail_id, format="raw",
                    fields="id,labelIds,internalDate,raw",
                )
            )
            encoded = response.get("raw")
            if response.get("id") != gmail_id or not isinstance(encoded, str):
                raise m.MigrationError("Gmail returned an unexpected receipt or missing raw data.")
            remote_raw = base64.b64decode(
                encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True
            )
            remote_mime = mime_inventory(remote_raw)
            remote_message = m.BytesParser(policy=m.policy.default).parsebytes(remote_raw)
            metadata = {
                **{key: value for key, value in response.items() if key != "raw"},
                "payload": {"headers": [
                    {"name": name, "value": str(value)}
                    for name, value in remote_message.items()
                ]},
            }
            issues = inventory_issues(expected_mime, remote_mime)
            issues.extend(m.verify_readback_payload(
                row, gmail_id, metadata,
                m.expected_label_ids_for_row(row, checkpoint.get("gmail_labels", {})),
            ))
            report["rows"].append({
                "item_key": row["item_key"],
                "relative_path": row["relative_path"],
                "gmail_message_id": gmail_id,
                "prepared_sha256": m.sha256_bytes(prepared),
                "gmail_raw_sha256": m.sha256_bytes(remote_raw),
                "source_mime": expected_mime,
                "gmail_mime": remote_mime,
                "issues": issues,
                "ok": not issues,
            })
        for path, fingerprint in original_hashes.items():
            if m.sha256_file(path) != fingerprint:
                raise m.MigrationError("Profile, manifest, or checkpoint changed during verification.")
        for row, state in verified:
            # Rechecks each local source against the frozen manifest without mutation.
            m.source_bytes_for_state(profile, row, state)
        report["ok"] = len(report["rows"]) == EXPECTED_RECEIPTS and all(row["ok"] for row in report["rows"])
    except Exception as exc:
        # Do not print remote bodies, credential-bearing exception text, or traceback.
        report["error_type"] = type(exc).__name__
        report["ok"] = False
    report["checked_count"] = len(report["rows"])
    report["passed_count"] = sum(row["ok"] for row in report["rows"])
    m.write_json_atomic(REPORT, report)
    print(json.dumps({key: report[key] for key in ("ok", "checked_count", "passed_count")}))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit("Archived reference variant. Use the configurable v2 engine at the repository root.")
    raise SystemExit(main())
