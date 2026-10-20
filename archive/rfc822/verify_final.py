# Sanitized historical reference: source-specific evidence and live configuration are not distributed.
#!/usr/bin/env python3
"""Bounded read-only Gmail verification of the completed 951-row Inbox snapshot.

Never changes checkpoint, source files, Gmail content, labels, or read state.
The shared credential loader may refresh its saved OAuth credential. Holds the
runner's destination and checkpoint lock inodes through read-only file handles.
"""
from __future__ import annotations

from contextlib import contextmanager
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import zipfile

import runner
import verify_pilot


m = runner.engine
HERE = Path(__file__).resolve().parent
MAILBOX = 'example-49d20801@example.org'
SOURCE_COUNT = 951
BASELINE_COUNT = 3
SOURCE_ROOT = Path('/private/migration-example/source-export')
OUTPUT = HERE / "final-verification.json"
RESULT = HERE / "RUN_RESULT.md"
MAX_INVENTORY_PAGES = 20
DIRECT_STATUSES = {"verified", "preexisting_reviewed"}
LOCAL_ONLY_STATUSES = {"local_only_reviewed", "duplicate_local_only_reviewed"}
CONTENT_REPAIR_SOURCE_SHA256 = '00000000000000000000000000000000000000000000000000000000000035b4'


def require(condition, message):
    if not condition:
        raise m.MigrationError(message)


@contextmanager
def readonly_lock(path):
    """Require an existing runner lock; do not create or truncate its inode."""
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as handle:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise m.MigrationError("Migration lock is still in use.") from exc
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


@contextmanager
def migration_locks(profile):
    digest = hashlib.sha256(profile.destination.encode("utf-8")).hexdigest()
    destination = runner.DESTINATION_LOCK_DIR / f"{digest}.lock"
    checkpoint = profile.checkpoint_path.with_name(profile.checkpoint_path.name + ".lock")
    with readonly_lock(destination), readonly_lock(checkpoint):
        yield


def validate_completion(profile, manifest, checkpoint, final):
    require(profile.source_root == SOURCE_ROOT, "Unexpected source root.")
    require(profile.custom_label_policy == "none", "Custom-label policy changed.")
    require(len(manifest["messages"]) == SOURCE_COUNT, "Frozen denominator changed.")
    require(final.get("complete") is True, "Import final report is not complete.")
    current = m.build_report(profile, manifest, checkpoint)
    for key in (
        "migration_id", "source_mailbox", "destination", "source_eml_denominator",
        "status_counts", "complete", "accounted_complete", "gmail_complete",
        "gmail_covered_source_rows", "local_only_reviewed", "unique_gmail_message_ids",
        "final_reconciliation_verified", "final_reconciliation_failure_rows",
        "unresolved_extra_candidate_rows",
    ):
        require(final.get(key) == current.get(key), "Final report differs from current checkpoint.")
    require(current["accounted_complete"] is True, "Some frozen rows are not terminal.")
    require(current["final_reconciliation_verified"] is True, "Engine final reconciliation is not verified.")
    require(not current["final_reconciliation_failure_rows"], "Engine final readback has failures.")
    require(not current["unresolved_extra_candidate_rows"], "Unresolved additional Gmail candidates remain.")
    for state in checkpoint["states"].values():
        require(state["status"] in DIRECT_STATUSES | LOCAL_ONLY_STATUSES | {"duplicate_source_reviewed"},
                "Unsupported terminal outcome or manual exemption.")
        require(not state.get("replacement"), "Replacement-source exemption is not accepted.")
    return current


def audit_sources(profile, manifest, provenance):
    require(provenance.get("source_mailbox") == MAILBOX, "Provenance mailbox differs.")
    require(Path(provenance["source_root"]).resolve() == profile.source_root == SOURCE_ROOT,
            "Provenance source root differs.")
    require(provenance.get("source_count") == SOURCE_COUNT, "Provenance denominator differs.")
    rows = {row["relative_path"]: row for row in manifest["messages"]}
    original = {row["relative_path"]: row for row in provenance["source_files"]}
    require(len(original) == len(provenance["source_files"]) == SOURCE_COUNT,
            "Provenance paths are missing or duplicated.")
    require(set(original) == set(rows), "Manifest and provenance path inventories differ.")
    for relative, row in rows.items():
        for key in ("source_sha256", "source_size_bytes"):
            require(original[relative][key] == row[key], "Manifest differs from preserved source evidence.")
    require(len({row["source_sha256"] for row in rows.values()}) == SOURCE_COUNT,
            "Frozen source hashes are not unique.")
    m.validate_source_snapshot(profile, manifest)
    require(provenance["source_total_bytes"] == manifest["source_total_bytes"],
            "Source total byte denominator differs.")
    archive_path = Path(provenance["source_zip"]).resolve()
    require(archive_path == SOURCE_ROOT.with_suffix(".zip"), "Unexpected original ZIP path.")
    require(archive_path.stat().st_size == provenance["source_zip_size_bytes"], "Original ZIP size changed.")
    observed_hash = m.sha256_file(archive_path)
    require(observed_hash == provenance["source_zip_sha256"], "Original ZIP hash changed.")
    with zipfile.ZipFile(archive_path) as archive:
        members = [item for item in archive.infolist() if not item.is_dir()]
        by_name = {item.filename: item for item in members}
        require(len(members) == len(by_name) == SOURCE_COUNT, "Original ZIP inventory differs.")
        for row in original.values():
            item = by_name.get(row["zip_member_decoded_name"])
            require(item is not None and item.file_size == row["source_size_bytes"]
                    and f"{item.CRC:08x}" == row["zip_member_crc32_hex"] == row["extracted_crc32_hex"]
                    and row["zip_member_size_crc_match"] is True,
                    "Original ZIP-to-extracted-file provenance differs.")
    return {
        "source_sha256_verified_count": SOURCE_COUNT,
        "source_total_bytes": manifest["source_total_bytes"],
        "originals_preserved": True,
        "source_zip": str(archive_path),
        "source_zip_sha256": observed_hash,
        "zip_sha256_verified": True,
        "zip_member_provenance_verified_count": SOURCE_COUNT,
    }


def list_all_gmail_ids(service):
    ids, tokens, token = set(), set(), None
    for page in range(1, MAX_INVENTORY_PAGES + 1):
        kwargs = {"userId": "me", "includeSpamTrash": True, "maxResults": 500,
                  "fields": "messages/id,nextPageToken"}
        if token is not None:
            kwargs["pageToken"] = token
        response = m.execute_idempotent(lambda kwargs=kwargs: service.users().messages().list(**kwargs))
        for message in response.get("messages", []):
            gmail_id = message.get("id")
            require(isinstance(gmail_id, str) and bool(gmail_id), "Gmail inventory returned an empty ID.")
            require(gmail_id not in ids, "Gmail inventory repeated an ID across pages.")
            ids.add(gmail_id)
        token = response.get("nextPageToken")
        if not token:
            return ids, page
        require(token not in tokens, "Gmail inventory repeated a page token.")
        tokens.add(token)
    raise m.MigrationError("Gmail inventory exceeded the bounded page limit.")


def baseline_checks(before, after_ids, after_labels, receipt_ids):
    require(before.get("destination") == MAILBOX
            and before.get("gmail_profile", {}).get("emailAddress") == MAILBOX,
            "Gmail baseline belongs to another account.")
    baseline_ids = {str(message["id"]) for message in before["messages"]}
    require(len(baseline_ids) == len(before["messages"]) == BASELINE_COUNT,
            "Gmail baseline denominator changed.")
    before_custom = {str(label["id"]) for label in before["labels"]["labels"] if label.get("type") == "user"}
    after_custom = {str(label["id"]) for label in after_labels if label.get("type") == "user"}
    return {
        "baseline_count": len(baseline_ids),
        "missing_baseline_ids": sorted(baseline_ids - after_ids),
        "missing_receipt_ids": sorted(receipt_ids - after_ids),
        "new_custom_label_ids": sorted(after_custom - before_custom),
        "baseline_custom_label_count": len(before_custom),
        "current_custom_label_count": len(after_custom),
        "current_gmail_id_count": len(after_ids),
        "additional_ids_not_baseline_or_receipts": sorted(after_ids - baseline_ids - receipt_ids),
    }


def verify_content_repair(service, profile, row, state):
    """One audited source only: compare decoded MIME content after representation repair."""
    require(row["source_sha256"] == CONTENT_REPAIR_SOURCE_SHA256,
            "Content repair check is restricted to the audited source625 hash.")
    if state["status"] in LOCAL_ONLY_STATUSES:
        return {"item_key": row["item_key"], "status": "preserved_local_only", "gmail_reads": 0}
    require(state["status"] == "verified", "Repaired source lacks a verified direct receipt.")
    gmail_id = str(state["gmail_message_id"])
    prepared, _ = m.source_bytes_for_state(profile, row, state)
    expected_mime = verify_pilot.mime_inventory(prepared)
    response = m.execute_idempotent(lambda: service.users().messages().get(
        userId="me", id=gmail_id, format="raw", fields="id,labelIds,internalDate,raw"))
    encoded = response.get("raw")
    require(response.get("id") == gmail_id and isinstance(encoded, str),
            "Repaired-source raw read returned an unexpected receipt.")
    raw = base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
    observed_mime = verify_pilot.mime_inventory(raw)
    message = m.BytesParser(policy=m.policy.default).parsebytes(raw)
    metadata = {**{key: value for key, value in response.items() if key != "raw"},
                "payload": {"headers": [{"name": name, "value": str(value)}
                                         for name, value in message.items()]}}
    issues = verify_pilot.inventory_issues(expected_mime, observed_mime)
    issues += m.verify_readback_payload(row, gmail_id, metadata,
                                       m.expected_label_ids_for_row(row, {}))
    return {"item_key": row["item_key"], "gmail_message_id": gmail_id,
            "source_sha256": row["source_sha256"], "prepared_sha256": m.sha256_bytes(prepared),
            "gmail_raw_sha256": m.sha256_bytes(raw), "source_mime": expected_mime,
            "gmail_mime": observed_mime, "issues": issues, "ok": not issues, "gmail_reads": 1,
            "scope": "Audited source625 only: decoded MIME parts and primary headers/date/labels"}


def verify_locked(profile, report):
    report["stage"] = "completed_state_gate"
    final = m.load_json(profile.report_path)
    # Gate before credentials or any Gmail calls, including manifest analysis.
    require(final.get("complete") is True, "Import final report is not complete.")
    immutable = (profile.path, profile.manifest_path, profile.checkpoint_path, profile.report_path,
                 HERE / "source-provenance.json", HERE / "gmail-before-import.json")
    before_hashes = {path: m.sha256_file(path) for path in immutable}
    manifest = m.load_manifest(profile)
    checkpoint = m.load_checkpoint(profile, manifest, create=False)
    current = validate_completion(profile, manifest, checkpoint, final)
    report.update({key: current[key] for key in (
        "accounted_complete", "gmail_complete", "status_counts", "gmail_covered_source_rows",
        "local_only_reviewed", "unique_gmail_message_ids",
    )})
    report["stage"] = "source_preservation"
    report["source_preservation"] = audit_sources(profile, manifest, m.load_json(HERE / "source-provenance.json"))
    receipt_rows, receipt_ids = [], set()
    for row in manifest["messages"]:
        state = checkpoint["states"][row["item_key"]]
        if state["status"] not in DIRECT_STATUSES:
            continue
        gmail_id = str(state["gmail_message_id"])
        require(gmail_id not in receipt_ids, "Two source rows claim the same Gmail receipt.")
        receipt_ids.add(gmail_id)
        prepared, _ = m.source_bytes_for_state(profile, row, state)
        if state["status"] == "verified":
            require(m.sha256_bytes(prepared) == state["verified_prepared_sha256"],
                    "Verified receipt upload hash differs from its source preparation.")
        receipt_rows.append((row, state, gmail_id))
    require(len(receipt_ids) == current["unique_gmail_message_ids"], "Receipt denominator differs.")
    require(len(receipt_ids) <= SOURCE_COUNT, "Receipt read bound exceeded.")

    report["stage"] = "gmail_receipt_readback"
    _, service, _ = m.load_authorized_credentials(profile)
    report["exact_account_guard_passed"] = True
    observed_labels = {}
    for row, state, gmail_id in receipt_rows:
        payload = m.readback_message(service, gmail_id)
        observed_labels[gmail_id] = {str(value) for value in payload.get("labelIds", [])}
        issues = m.verify_readback_payload(row, gmail_id, payload,
                    m.expected_label_ids_for_row(row, checkpoint.get("gmail_labels", {})))
        report["rows"].append({"item_key": row["item_key"], "gmail_message_id": gmail_id,
                               "status": state["status"], "issues": issues, "ok": not issues})
        if len(report["rows"]) % 100 == 0:
            print(json.dumps({"phase": "final_readback", "checked": len(report["rows"]),
                              "total_receipts": len(receipt_rows)}), flush=True)
    report["readback_verified_receipts"] = sum(row["ok"] for row in report["rows"])
    passed_keys = {row["item_key"] for row in report["rows"] if row["ok"]}
    duplicate_count = 0
    for row in manifest["messages"]:
        state = checkpoint["states"][row["item_key"]]
        if state["status"] == "duplicate_source_reviewed":
            require(state["represented_by_item_key"] in passed_keys,
                    "Duplicate source row lacks a currently verified canonical receipt.")
            canonical = checkpoint["states"][state["represented_by_item_key"]]
            require(state["represented_by_gmail_id"] == canonical["gmail_message_id"]
                    and state["represented_prepared_sha256"] == row["prepared_sha256"]
                    == canonical["verified_prepared_sha256"],
                    "Exact-duplicate canonical byte or receipt mapping differs.")
            require(set(state.get("canonical_union_label_ids", [])).issubset(
                        observed_labels[canonical["gmail_message_id"]]),
                    "Exact-duplicate canonical receipt lacks union folder labels.")
            duplicate_count += 1
    report["readback_verified_source_rows"] = report["readback_verified_receipts"] + duplicate_count
    report["exact_duplicate_source_rows"] = duplicate_count
    report["stage"] = "audited_content_repair"
    repaired_rows = [row for row in manifest["messages"]
                     if row["source_sha256"] == CONTENT_REPAIR_SOURCE_SHA256]
    require(len(repaired_rows) == 1, "Audited source625 is missing or duplicated.")
    repaired_row = repaired_rows[0]
    report["audited_content_repair"] = verify_content_repair(
        service, profile, repaired_row, checkpoint["states"][repaired_row["item_key"]])
    report["stage"] = "gmail_inventory"
    after_ids, pages = list_all_gmail_ids(service)
    labels = m.execute_idempotent(lambda: service.users().labels().list(userId="me"))
    require(isinstance(labels.get("labels"), list), "Gmail label inventory is missing.")
    report["inventory"] = baseline_checks(m.load_json(HERE / "gmail-before-import.json"),
                                         after_ids, labels["labels"], receipt_ids)
    report["inventory"]["pages"] = pages
    report["stage"] = "final_immutability_check"
    for path, fingerprint in before_hashes.items():
        require(m.sha256_file(path) == fingerprint, "Frozen migration evidence changed during verification.")
    m.validate_source_snapshot(profile, manifest)
    report["migration_evidence_unchanged"] = True
    inventory = report["inventory"]
    report["ok"] = (all(row["ok"] for row in report["rows"])
                    and report["readback_verified_source_rows"] == current["gmail_covered_source_rows"]
                    and not inventory["missing_baseline_ids"]
                    and not inventory["missing_receipt_ids"]
                    and not inventory["new_custom_label_ids"]
                    and report["audited_content_repair"].get("ok",
                            report["audited_content_repair"].get("status") == "preserved_local_only"))
    # A verified local-only outcome can be fully accounted for without being in Gmail.
    report["gmail_complete"] = bool(report["ok"] and current["gmail_complete"]
                                    and report["readback_verified_source_rows"] == SOURCE_COUNT
                                    and current["local_only_reviewed"] == 0)
    report["stage"] = "finished"


def write_result(report):
    inventory = report.get("inventory", {})
    lines = [f"# example-49d20801@example.org migration result", "",
             f"Checked: {report['checked_at']}", "",
             f"Independent verification passed: **{str(report['ok']).lower()}**.",
             f"Frozen source: **{SOURCE_COUNT} Cafe24 Inbox EML files**.",
             f"Readback-verified Gmail receipts: **{report.get('readback_verified_receipts', 0)}**.",
             f"Readback-verified source rows: **{report.get('readback_verified_source_rows', 0)} / {SOURCE_COUNT}**.",
             f"Preserved local-only source rows: **{report.get('local_only_reviewed', 'not established')}**.",
             f"Accounted complete: **{str(report.get('accounted_complete', False)).lower()}**.",
             f"Gmail complete for this frozen Inbox snapshot: **{str(report.get('gmail_complete', False)).lower()}**.",
             f"Original Gmail baseline: **{BASELINE_COUNT} messages**; missing IDs: **{len(inventory.get('missing_baseline_ids', [])) if inventory else 'not checked'}**.",
             f"New custom labels: **{len(inventory.get('new_custom_label_ids', [])) if inventory else 'not checked'}**.", "",
             "All original EML hashes and the original ZIP hash are rechecked when source preservation passes. "
             "Receipt verification checks exact Gmail IDs, selected headers, historical internalDate, and expected Inbox labels. "
             "It does not assert universal raw-body or attachment byte equivalence.", "",
             "The bounded content check separately compares decoded MIME content for repaired source625 "
             "if Gmail holds its receipt; a local-only outcome is stated explicitly in the JSON report.", "",
             "Scope: the frozen 951-message Inbox export only. Sent, Drafts, Trash, Mail to Myself, "
             "later backup notifications, and subsequent messages are excluded. This is not a live mailbox sync. "
             "Gmail inventory is a paginated observation, not an atomic mailbox snapshot. "
             "Additional IDs beyond baseline and receipts may be concurrent deliveries and are reported separately.", "",
             "This verifier made no Gmail writes, sends, deletions, label changes, or read-state changes. "
             "The importer preserves source EMLs and its checkpoint remains unchanged by this verifier."]
    if not report["ok"]:
        lines += ["", f"Verification needs review at stage `{report['stage']}`; "
                   f"error type: `{report.get('error_type', 'check_mismatch')}`. See final-verification.json."]
    temporary = RESULT.with_suffix(".md.tmp")
    temporary.write_text("\n".join(lines) + "\n", encoding="utf-8")
    temporary.replace(RESULT)


def main():
    os.umask(0o077)
    report = {"schema_version": 1, "checked_at": m.utc_now(), "destination": MAILBOX,
              "source_mailbox": MAILBOX, "source_eml_denominator": SOURCE_COUNT,
              "gmail_writes": 0, "rows": [], "ok": False, "gmail_complete": False,
              "stage": "load_profile"}
    try:
        profile = m.load_profile(HERE / "profile.json")
        runner.guard_profile(profile)
        with migration_locks(profile):
            verify_locked(profile, report)
    except Exception as exc:
        # Exception text can contain mail content or credential-bearing URLs.
        report["error_type"] = type(exc).__name__
        report["ok"] = False
        report["gmail_complete"] = False
    report["finished_at"] = m.utc_now()
    m.write_json_atomic(OUTPUT, report)
    write_result(report)
    print(json.dumps({key: report.get(key) for key in (
        "ok", "accounted_complete", "gmail_complete", "readback_verified_receipts",
        "local_only_reviewed", "stage", "error_type")}), flush=True)
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit("Archived reference variant. Use the configurable v2 engine at the repository root.")
    raise SystemExit(main())
