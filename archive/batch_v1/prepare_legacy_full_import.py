# Sanitized historical reference: source-specific evidence and live configuration are not distributed.
#!/usr/bin/env python3
'Build the immutable, source-preserving mailbox full-import manifest.'

from __future__ import annotations

import argparse
import hashlib
import json
import os
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from legacy_common import (
    DATE_UTC_NORMALIZATION_IDS,
    DESTINATION,
    DUPLICATE_SKIP_TO_KEEP,
    EXPECTED_DUPLICATE_GROUPS,
    EXPECTED_RECEIVED_REPAIR_COUNT,
    EXPECTED_RECEIVED_REPAIR_ID_DIGEST,
    OAUTH_CLIENT_ID,
    SOURCE_BYTES,
    SOURCE_COUNT,
    SOURCE_FOLDER,
    SOURCE_ROOT,
    ArchiveError,
    archive_files,
    prepared_record,
)


PROJECT_ROOT = Path('/private/migration-example/how-x20-2')
PILOT_MANIFEST = PROJECT_ROOT / 'work/mailbox-gmail-pilot/manifest.json'
PILOT_CHECKPOINT = PROJECT_ROOT / 'work/mailbox-gmail-pilot/checkpoint.json'
DEFAULT_OUTPUT = PROJECT_ROOT / 'work/mailbox-gmail-full/manifest.json'
DEFAULT_CHECKPOINT = PROJECT_ROOT / 'work/mailbox-gmail-full/checkpoint.json'
FIRST_BATCH_QUERIES = PROJECT_ROOT / 'outputs/mailbox_full_first_batch_searches.txt'


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ArchiveError(f"Cannot read valid JSON from {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ArchiveError(f"Expected a JSON object in {path}.")
    return value


def write_json_atomic(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def pilot_receipts() -> dict[str, dict]:
    pilot_manifest = load_json(PILOT_MANIFEST)
    checkpoint = load_json(PILOT_CHECKPOINT)
    if checkpoint.get("pilot_status") != "verified_complete":
        raise ArchiveError("The five-message pilot is not recorded as verified complete.")
    checkpoint_states = checkpoint.get("messages", {})
    receipts = {}
    for row in pilot_manifest.get("messages", []):
        pilot_id = str(row["pilot_id"])
        state = checkpoint_states.get(pilot_id, {})
        if state.get("status") != "verified" or not state.get("gmail_message_id"):
            raise ArchiveError(f"Pilot {pilot_id} is not verified with a Gmail ID.")
        receipts[str(row["sha256"])] = {
            "pilot_id": pilot_id,
            "gmail_message_id": str(state["gmail_message_id"]),
            "verified_at": state.get("verified_manually_at"),
        }
    if len(receipts) != 5:
        raise ArchiveError("Expected exactly five unique verified pilot receipts.")
    return receipts


def stable_header_key(row: dict) -> tuple[str, ...]:
    return (
        row["message_id"],
        row["date_header"],
        row["from_header"],
        row["to_header"],
        row["cc_header"],
        row["subject_header"],
        row["body_sha256"],
    )


def priority_key(row: dict) -> tuple[int, int]:
    if row["source_id"] in DATE_UTC_NORMALIZATION_IDS:
        return (0, row["source_id"])
    if "cafe24_received_fold_space_v1" in row["repairs"]:
        return (1, row["source_id"])
    if row["source_size_bytes"] >= 25_000_000:
        return (2, row["source_id"])
    return (3, row["source_id"])


def build_manifest() -> dict:
    receipts = pilot_receipts()
    rows = []
    received_repair_ids = []
    by_message_id: dict[str, list[int]] = defaultdict(list)
    by_source_id = {}

    for path in archive_files():
        prepared, row = prepared_record(path)
        source_id = int(row["source_id"])
        if "cafe24_received_fold_space_v1" in row["repairs"]:
            received_repair_ids.append(source_id)
        by_message_id[row["message_id"]].append(source_id)
        by_source_id[source_id] = row
        rows.append(row)

    if len(received_repair_ids) != EXPECTED_RECEIVED_REPAIR_COUNT:
        raise ArchiveError("Received repair count no longer matches the archive audit.")
    repair_digest = hashlib.sha256(
        ",".join(str(item) for item in sorted(received_repair_ids)).encode("ascii")
    ).hexdigest()
    if repair_digest != EXPECTED_RECEIVED_REPAIR_ID_DIGEST:
        raise ArchiveError("Received repair membership no longer matches the archive audit.")

    duplicate_groups = {
        frozenset(ids) for ids in by_message_id.values() if len(ids) > 1
    }
    if duplicate_groups != EXPECTED_DUPLICATE_GROUPS:
        raise ArchiveError(f"Unexpected duplicate Message-ID groups: {duplicate_groups}")

    for skipped, kept in DUPLICATE_SKIP_TO_KEEP.items():
        if stable_header_key(by_source_id[skipped]) != stable_header_key(by_source_id[kept]):
            raise ArchiveError(f"Semantic duplicate pair {skipped}/{kept} changed.")

    pilot_count = 0
    skip_count = 0
    import_rows = []
    for row in rows:
        source_sha = row["source_sha256"]
        source_id = int(row["source_id"])
        row["item_key"] = source_sha
        if source_sha in receipts:
            receipt = receipts[source_sha]
            row["action"] = "already_imported_verified_pilot"
            row["pilot_id"] = receipt["pilot_id"]
            row["gmail_message_id"] = receipt["gmail_message_id"]
            row["pilot_verified_at"] = receipt["verified_at"]
            pilot_count += 1
        elif source_id in DUPLICATE_SKIP_TO_KEEP:
            kept_id = DUPLICATE_SKIP_TO_KEEP[source_id]
            row["action"] = "skip_semantic_duplicate"
            row["duplicate_of_source_id"] = kept_id
            row["duplicate_of_source_sha256"] = by_source_id[kept_id]["source_sha256"]
            skip_count += 1
        else:
            row["action"] = "import"
            import_rows.append(row)

    import_rows.sort(key=priority_key)
    for order, row in enumerate(import_rows, start=1):
        row["import_order"] = order

    if (len(rows), pilot_count, skip_count, len(import_rows)) != (2005, 5, 3, 1997):
        raise ArchiveError(
            "Reconciliation failed; expected 2005 = 5 pilot + 3 skipped + 1997 new."
        )

    selected_rows = [row for row in rows if row["action"] != "skip_semantic_duplicate"]
    selected_message_ids = [row["message_id"] for row in selected_rows]
    if len(set(selected_message_ids)) != 2002:
        raise ArchiveError("Selected Message-IDs are not exactly 2,002 unique values.")
    if sum(row["source_size_bytes"] for row in selected_rows) != 1_223_699_972:
        raise ArchiveError("Selected source-byte total no longer matches the audit.")
    if sum(row["prepared_size_bytes"] for row in selected_rows) != 1_223_700_201:
        raise ArchiveError("Prepared-byte total no longer matches the audit.")

    rows.sort(key=lambda row: int(row["source_id"]))
    manifest = {
        "schema_version": 1,
        "created_at": utc_now(),
        "purpose": "Cafe24 Inbox full migration to one verified Gmail mailbox",
        "source_mailbox": DESTINATION,
        "source_root": str(SOURCE_ROOT),
        "expected_source_folder": SOURCE_FOLDER,
        "source_eml_count": SOURCE_COUNT,
        "source_total_bytes": SOURCE_BYTES,
        "expected_destination": DESTINATION,
        "oauth_client_id": OAUTH_CLIENT_ID,
        "expected_checkpoint": str(DEFAULT_CHECKPOINT),
        "reconciliation": {
            "source_files": 2005,
            "already_imported_verified_pilot": 5,
            "semantic_duplicates_skipped": 3,
            "new_api_imports": 1997,
            "target_gmail_messages_from_archive": 2002,
        },
        "normalization": {
            "received_fold_repairs": len(received_repair_ids),
            "received_repair_id_digest": repair_digest,
            "unknown_utc_dates_preserved_and_interpreted_as_utc": len(
                DATE_UTC_NORMALIZATION_IDS
            ),
            "source_files_modified": 0,
        },
        "duplicate_policy": {
            str(skipped): kept for skipped, kept in sorted(DUPLICATE_SKIP_TO_KEEP.items())
        },
        "anomalies_preserved": {
            "missing_to_source_ids": [574, 580, 601],
            "missing_subject_source_ids": [650],
            "noncanonical_message_id_source_ids": [37, 342, 868, 1276, 1277, 1278],
        },
        "messages": rows,
    }
    return manifest


def write_first_batch_queries(manifest: dict, count: int = 25) -> None:
    rows = sorted(
        (row for row in manifest["messages"] if row["action"] == "import"),
        key=lambda row: int(row["import_order"]),
    )[:count]
    lines = [
        'mailbox full-import first-batch Gmail verification searches',
        'Destination: example-b54b38f4@example.org',
        "Before the batch: each query must return zero results.",
        "After the batch: each query must return exactly one Inbox result.",
        "",
    ]
    for row in rows:
        lines.append(
            f"source {row['source_id']}: in:inbox rfc822msgid:{row['message_id']}"
        )
    FIRST_BATCH_QUERIES.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--replace", action="store_true")
    args = parser.parse_args()
    if args.output.resolve() != DEFAULT_OUTPUT.resolve():
        parser.error("The full manifest path is frozen to the canonical work directory.")
    if args.output.exists() and not args.replace:
        parser.error("Manifest already exists; use --replace only before any full checkpoint exists.")
    if DEFAULT_CHECKPOINT.exists():
        parser.error("Refusing to rebuild a manifest after a full-import checkpoint exists.")
    try:
        manifest = build_manifest()
        write_json_atomic(args.output, manifest)
        write_first_batch_queries(manifest)
    except ArchiveError as exc:
        print(f"STOPPED: {exc}")
        return 2
    print("manifest:", args.output)
    print("source_files:", manifest["reconciliation"]["source_files"])
    print("pilot_already_verified:", manifest["reconciliation"]["already_imported_verified_pilot"])
    print("semantic_duplicates_skipped:", manifest["reconciliation"]["semantic_duplicates_skipped"])
    print("new_api_imports:", manifest["reconciliation"]["new_api_imports"])
    print("target_gmail_messages:", manifest["reconciliation"]["target_gmail_messages_from_archive"])
    print("source_files_modified: 0")
    print("gmail_writes: 0")
    return 0


if __name__ == "__main__":
    raise SystemExit("Archived reference variant. Use the configurable v2 engine at the repository root.")
    raise SystemExit(main())
