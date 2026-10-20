# Sanitized historical reference: source-specific evidence and live configuration are not distributed.
#!/usr/bin/env python3
"Independently verify the finished Raw-header run, without changing migration state.\n\nHolds the existing checkpoint lock via a read-only file handle, requires the\nengine's completed terminal report, rehashes both original extracted snapshots\nand staging, and makes only Gmail read calls. The engine may refresh its saved\nOAuth credential. Never execute concurrently with the migration runner.\n"

from __future__ import annotations

from collections import defaultdict
from contextlib import contextmanager
import fcntl
import json
from pathlib import Path

import raw_header_runner


m = raw_header_runner.engine
HERE = Path(__file__).resolve().parent
MAILBOX = 'example-a88c3515@example.org'
SOURCE_COUNT = 2897
BASELINE_COUNT = 524
OUTPUT = HERE / "final-verification.json"
RESULT = HERE / "RUN_RESULT.md"


@contextmanager
def read_only_checkpoint_lock(checkpoint_path: Path):
    """Use the runner's existing lock inode without creating/truncating it."""
    lock_path = checkpoint_path.with_name(checkpoint_path.name + ".lock")
    with lock_path.open("rb") as handle:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise m.MigrationError("Migration checkpoint is still in use.") from exc
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise m.MigrationError(message)


def audit_sources(profile, manifest, provenance):
    require(provenance.get("mailbox") == MAILBOX, "Provenance mailbox mismatch.")
    for key, expected in (("union_eml_count", 2897), ("newer_count", 2870), ("older_count", 2854), ("older_only_count", 27)):
        require(provenance.get(key) == expected, "Frozen provenance denominator changed.")
    expected_rows = {row["relative_path"]: row for row in manifest["messages"]}
    require(len(expected_rows) == SOURCE_COUNT, "Manifest source denominator changed.")
    staged_paths = {path.relative_to(profile.source_root).as_posix(): path for path in m.discover_eml_files(profile.source_root)}
    require(set(staged_paths) == set(expected_rows), "Staged source path inventory changed.")
    for relative, row in expected_rows.items():
        path = staged_paths[relative]
        require(path.stat().st_size == row["source_size_bytes"] and m.sha256_file(path) == row["source_sha256"], "Staged source bytes changed.")
    source_hashes = {row["source_sha256"] for row in expected_rows.values()}
    require(len(source_hashes) == SOURCE_COUNT, "Frozen sources are no longer SHA-256-distinct.")
    staged_provenance = {row["relative_path"]: row for row in provenance["staged_rows"]}
    require(set(staged_provenance) == set(expected_rows), "Staged provenance inventory differs.")
    for relative, row in expected_rows.items():
        require(staged_provenance[relative]["source_sha256"] == row["source_sha256"], "Staged provenance SHA-256 differs.")

    summaries, originals_by_hash, snapshot_hash_sets = [], defaultdict(list), []
    snapshots = provenance["source_inventory"]
    require(len(snapshots) == 2, "Expected both original extracted snapshots.")
    for snapshot in snapshots:
        root = Path(snapshot["extracted_root"]).resolve()
        rows = snapshot["rows"]
        recorded_paths = {Path(row["path"]).resolve() for row in rows}
        observed_paths = {path.resolve() for path in m.discover_eml_files(root)}
        require(len(rows) == snapshot["eml_count"] == len(recorded_paths), "Original snapshot count differs.")
        require(recorded_paths == observed_paths, "Original snapshot file inventory changed.")
        snapshot_hashes = set()
        for row in rows:
            path = Path(row["path"]).resolve()
            require(m.is_within(path, root), "Original source escapes its recorded snapshot.")
            require(path.stat().st_size == row["size"] and m.sha256_file(path) == row["sha256"], "Original source bytes changed.")
            staged = expected_rows.get(row["staged_path"])
            require(staged is not None and staged["source_sha256"] == row["sha256"], "Original-to-staged mapping differs.")
            snapshot_hashes.add(row["sha256"])
            originals_by_hash[row["sha256"]].append(str(path))
        summaries.append({"extracted_root": str(root), "eml_count": len(rows), "sha256_verified_count": len(rows), "all_preserved": True})
        snapshot_hash_sets.append(snapshot_hashes)
    require({entry["eml_count"] for entry in summaries} == {2870, 2854}, "Original snapshot denominators differ.")
    newer = snapshot_hash_sets[next(i for i, entry in enumerate(summaries) if entry["eml_count"] == 2870)]
    older = snapshot_hash_sets[next(i for i, entry in enumerate(summaries) if entry["eml_count"] == 2854)]
    require(newer | older == source_hashes and len(older - newer) == 27, "Original snapshot union differs.")
    return {
        "latest_snapshot_rows": 2870,
        "older_snapshot_rows": 2854,
        "older_only_rows": 27,
        "union_rows": SOURCE_COUNT,
        "staged_sha256_verified_count": len(staged_paths),
        "original_extracted_sha256_verified_count": sum(entry["eml_count"] for entry in summaries),
        "original_snapshots": summaries,
        "originals_preserved": True,
        "zip_archives_rehashed_by_this_verifier": False,
    }, originals_by_hash


def list_all_gmail_ids(service):
    ids, tokens, pages, token = set(), set(), 0, None
    while True:
        kwargs = {"userId": "me", "includeSpamTrash": True, "maxResults": 500, "fields": "messages/id,nextPageToken"}
        if token is not None:
            kwargs["pageToken"] = token
        response = m.execute_idempotent(lambda kwargs=kwargs: service.users().messages().list(**kwargs))
        pages += 1
        for message in response.get("messages", []):
            gmail_id = str(message.get("id", ""))
            require(bool(gmail_id), "Gmail inventory returned an empty ID.")
            ids.add(gmail_id)
        token = response.get("nextPageToken")
        if not token:
            return ids, pages
        require(token not in tokens, "Gmail inventory repeated a page token.")
        tokens.add(token)


def validate_manual_readback(evidence, manifest_by_key, states):
    """Bind the recorded recipient-order audit to this exact terminal receipt."""
    item_key = evidence.get("item_key")
    require(evidence.get("destination") == MAILBOX and item_key in manifest_by_key and item_key in states, "Manual raw-audit identity differs.")
    row, state = manifest_by_key[item_key], states[item_key]
    require(state.get("status") == "verified_manual", "Raw-audited exception is not manually verified.")
    require(bool(evidence.get("gmail_message_id")) and evidence["gmail_message_id"] == state.get("gmail_message_id"), "Manual raw-audit Gmail receipt differs.")
    for field in ("source_sha256", "prepared_sha256"):
        require(evidence.get(field) == row[field] == state[field], "Manual raw-audit source or prepared fingerprint differs.")
    require(evidence.get("metadata_issues") == ["readback To header differs from the source"], "Manual raw audit contains another metadata issue.")
    require(evidence.get("raw_original_to_headers_equal") is True and evidence.get("source_files_unchanged") is True, "Manual raw-audit preservation evidence is incomplete.")
    require(evidence.get("source_to_value") == evidence.get("raw_to_value") == row.get("to"), "Manual raw-audit To value differs from the manifest.")
    recipients = set(m.normalized_address_header(str(row.get("to", ""))) or ())
    require(bool(recipients) and all(set(evidence.get(field, [])) == recipients for field in ("source_to_addresses", "metadata_to_addresses", "raw_to_addresses")), "Manual raw-audit recipient identities differ.")
    source_mime, gmail_mime = evidence.get("source_mime"), evidence.get("gmail_mime")
    require(isinstance(source_mime, dict) and bool(source_mime.get("leaves")) and source_mime == gmail_mime and evidence.get("mime_issues") == [], "Manual raw-audit MIME evidence differs.")
    raw_hash = str(evidence.get("gmail_raw_sha256", ""))
    require(len(raw_hash) == 64 and all(char in '00000000000061cc' for char in raw_hash), "Manual Gmail raw fingerprint is invalid.")
    return {
        "evidence_file": str(HERE / "recipient-header-review.json"),
        "checked_at": evidence.get("checked_at"),
        "item_key": item_key,
        "gmail_message_id": evidence["gmail_message_id"],
        "source_sha256": row["source_sha256"],
        "prepared_sha256": row["prepared_sha256"],
        "gmail_raw_sha256": raw_hash,
        "unique_recipient_count": len(recipients),
        "decoded_leaf_count": len(source_mime["leaves"]),
        "raw_original_to_headers_equal": True,
        "recipient_identity_sets_equal": True,
        "decoded_mime_inventory_equal": True,
        "accepted_metadata_exception": "To recipient order differs in Gmail metadata; original raw header is preserved",
        "later_engine_manual_row_check_scope": "Gmail receipt ID and Message-ID",
    }


def validate_automatic_raw_readback(evidence, evidence_path, manifest_by_key, states):
    """Bind an automatic full-message comparison to its terminal Gmail receipt."""
    key = evidence.get("item_key")
    require(evidence.get("passed") is True and evidence.get("destination") == MAILBOX,
            'Automatic raw audit is not a passed Raw-header comparison.')
    require(key in manifest_by_key and key in states, "Automatic raw-audit source is unknown.")
    row, state = manifest_by_key[key], states[key]
    require(state.get("status") in {"verified", "verified_manual"},
            "Automatic raw-audit receipt is not verified.")
    require(evidence.get("gmail_message_id") == state.get("gmail_message_id")
            and bool(evidence.get("gmail_message_id")), "Automatic raw-audit receipt differs.")
    for field in ("source_sha256", "prepared_sha256"):
        require(evidence.get(field) == row[field] == state[field],
                "Automatic raw-audit source or prepared fingerprint differs.")
    allowed = {f"readback {field} header differs from the source" for field in ("From", "To", "Cc", "Subject")}
    issues = evidence.get("original_metadata_issues")
    require(isinstance(issues, list) and bool(issues) and set(issues) <= allowed,
            "Automatic raw audit attempted to waive another validation check.")
    require(evidence.get("primary_headers_equal") is True and evidence.get("mime_equal") is True
            and evidence.get("source_files_unchanged") is True
            and evidence.get("raw_readback_issues") == [],
            "Automatic raw comparison did not establish header and content equality.")
    source_headers, remote_headers = evidence.get("source_primary_raw_headers"), evidence.get("gmail_primary_raw_headers")
    require(isinstance(source_headers, dict) and bool(source_headers) and source_headers == remote_headers,
            "Automatic raw primary-header evidence differs.")
    source_mime, remote_mime = evidence.get("source_mime"), evidence.get("gmail_mime")
    require(isinstance(source_mime, list) and bool(source_mime) and source_mime == remote_mime,
            "Automatic raw MIME-tree evidence differs.")
    raw_payload = evidence.get("raw_readback_payload")
    expected_labels = m.expected_label_ids_for_row(row, {})
    require(isinstance(raw_payload, dict) and evidence.get("expected_label_ids") == expected_labels
            and not m.verify_readback_payload(row, state["gmail_message_id"], raw_payload, expected_labels),
            "Recorded automatic raw metadata does not pass the source checks.")
    raw_hash = str(evidence.get("gmail_raw_sha256", ""))
    require(len(raw_hash) == 64 and all(c in '00000000000061cc' for c in raw_hash),
            "Automatic raw Gmail fingerprint is invalid.")
    return {"evidence_file": str(evidence_path), "checked_at": evidence.get("checked_at"),
            "item_key": key, "gmail_message_id": evidence["gmail_message_id"],
            "source_sha256": row["source_sha256"], "prepared_sha256": row["prepared_sha256"],
            "gmail_raw_sha256": raw_hash, "original_metadata_issues": issues,
            "primary_headers_equal": True, "decoded_mime_equal": True,
            "fresh_raw_metadata_checks_passed": True}


def run_result_text(report):
    if not report.get("ok"):
        return (
            'Raw-header migration final verification is incomplete.\n\n'
            f"Stopped at `{report.get('stage', 'unknown')}` with `{report.get('error_type', 'validation_failure')}`. "
            "No complete migration claim follows from this report. See final-verification.json.\n"
        )
    engine_report = report["engine_completion"]
    presence = report["gmail_presence"]
    local_count = len(report["local_only_exceptions"])
    fidelity = report["raw_mime_fidelity_scope"]
    manual_count = len(report.get("manual_raw_readback_evidence", []))
    automatic_count = len(report.get("automatic_raw_readback_evidence", []))
    manual_text = (
        f"An additional {manual_count} recipient-order exception was accepted after a separate raw audit confirmed "
        "the original To header, recipient identity set and decoded MIME content. "
        if manual_count else ""
    )
    return (
        f"The example-a88c3515@example.org Inbox archive run accounted for all {SOURCE_COUNT:,} frozen source messages: "
        f"{engine_report['gmail_covered_source_rows']:,} source rows are represented in Gmail and "
        f"{local_count:,} remain preserved locally.\n\n"
        f"The source denominator is 2,870 messages from the latest snapshot plus 27 older-only messages. "
        f"Both original extracted snapshots were rehashed ({report['sources']['original_extracted_sha256_verified_count']:,} EML files), "
        f"along with all {SOURCE_COUNT:,} staged messages; all matched their recorded SHA-256 hashes. "
        "This verification did not rehash the original ZIP archives.\n\n"
        f"A complete Gmail ID enumeration including Spam and Trash found all {presence['migration_receipt_count']:,} "
        f"checkpoint receipt IDs and all {presence['baseline_id_count']:,} pre-import IDs. "
        f"The enumeration contained {presence['live_id_count']:,} distinct IDs and "
        f"{presence['additional_unowned_id_count']:,} IDs outside the baseline and migration receipts. "
        "Baseline ID presence does not independently prove unchanged baseline content or labels.\n\n"
        "The engine completed its final receipt reconciliation, with manual exceptions recorded separately. "
        + manual_text +
        f"Decoded body and attachment fidelity was independently checked for five pilot messages plus "
        f"{manual_count} recorded manual raw-audit exception(s) and {automatic_count} automatic full-message "
        "comparisons for metadata header differences, covering "
        f"{fidelity['verified_distinct_message_count']} distinct messages. "
        "Full-run byte equivalence is not claimed.\n\n"
        f"All source outcomes are terminal. Strict all-source Gmail completeness is "
        f"`{str(engine_report['gmail_complete']).lower()}`; local-only exceptions and original file paths "
        "are listed in final-verification.json.\n\n"
        "Scope is the two Inbox archives. Sent, To Me, custom folders, Drafts, Spam and Trash archives, "
        "post-export arrivals, ongoing delivery, MX and routing are excluded. No live Cafe24 folder inventory "
        "was collected for this run, so live source-to-Gmail mailbox equality is not established.\n"
    )


def main():
    report = {"checked_at": m.utc_now(), "destination": MAILBOX, "ok": False, "gmail_writes": 0, "stage": "local_completion_gate"}
    try:
        profile = m.load_profile(HERE / "profile.json")
        require(profile.destination == profile.source_mailbox == MAILBOX, "Verifier is restricted to SG.")
        with read_only_checkpoint_lock(profile.checkpoint_path):
            report["exclusive_read_only_lock_acquired"] = True
            manifest = m.load_manifest(profile)
            checkpoint = m.load_checkpoint(profile, manifest, create=False)
            final_report = m.load_json(profile.report_path)
            calculated = m.build_report(profile, manifest, checkpoint)
            require(final_report.get("complete") is True and calculated["complete"] is True, "Engine run is not complete.")
            require(all(state["status"] in m.TERMINAL_STATUSES for state in checkpoint["states"].values()), "Nonterminal checkpoint row remains.")
            semantic_keys = (
                "migration_id", "source_mailbox", "destination", "source_eml_denominator", "status_counts",
                "accounted_for", "blocking", "pending_or_inflight", "complete", "accounted_complete",
                "gmail_complete", "gmail_message_presence_complete", "folder_label_complete",
                "gmail_covered_rows_folder_complete", "final_reconciliation_verified",
                "final_reconciliation_failure_rows", "unresolved_extra_candidate_rows",
                "google_verified", "preexisting_reviewed", "gmail_covered_source_rows",
                "folder_label_covered_source_rows", "unique_gmail_message_ids", "local_only_reviewed",
            )
            require(all(final_report.get(key) == calculated.get(key) for key in semantic_keys), "Engine report differs from current checkpoint.")
            require(calculated["final_reconciliation_verified"] and calculated["gmail_covered_rows_folder_complete"], "Engine final readback or folder checks are incomplete.")
            require(not calculated["final_reconciliation_failure_rows"] and not calculated["unresolved_extra_candidate_rows"], "Unresolved reconciliation exception remains.")
            report["engine_completion"] = {key: calculated[key] for key in semantic_keys}
            manual_evidence_path = HERE / "recipient-header-review.json"
            automatic_evidence_paths = tuple(sorted((profile.state_dir / "raw-header-verifications").glob("*.json")))
            protected = (profile.path, profile.manifest_path, profile.checkpoint_path, profile.report_path, HERE / "source-provenance.json", HERE / "gmail-before-import.json", HERE / "pilot-content-verification.json") + ((manual_evidence_path,) if manual_evidence_path.is_file() else ()) + automatic_evidence_paths
            protected_hashes = {path: m.sha256_file(path) for path in protected}

            report["stage"] = "source_preservation"
            provenance = m.load_json(HERE / "source-provenance.json")
            report["sources"], originals_by_hash = audit_sources(profile, manifest, provenance)
            manifest_by_key = m.row_by_key(manifest)
            local_only = []
            for item_key, state in checkpoint["states"].items():
                if state["status"] not in {"local_only_reviewed", "duplicate_local_only_reviewed"}:
                    continue
                row = manifest_by_key[item_key]
                require(state.get("source_preserved") is True, "Local-only source has no preservation decision.")
                local_only.append({
                    "item_key": item_key, "status": state["status"], "relative_path": row["relative_path"],
                    "source_sha256": row["source_sha256"], "prepared_sha256": row["prepared_sha256"],
                    "original_paths": originals_by_hash[row["source_sha256"]],
                    "decision": state.get("decision"), "decision_reason": state.get("decision_reason"),
                    "http_status": state.get("http_status"), "google_error_reasons": state.get("google_error_reasons", []),
                    "google_error": state.get("google_error"), "represented_by_item_key": state.get("represented_by_item_key"),
                    "original_sha256_verified": True,
                })
            require(len(local_only) == calculated["local_only_reviewed"], "Local-only exception count differs.")
            report["local_only_exceptions"] = local_only
            receipts = {str(state["gmail_message_id"]) for state in checkpoint["states"].values() if state.get("gmail_message_id")}
            require(len(receipts) == calculated["unique_gmail_message_ids"], "Receipt denominator differs.")
            baseline = m.load_json(HERE / "gmail-before-import.json")
            require(baseline.get("profile", {}).get("emailAddress", "").lower() == MAILBOX, "Baseline mailbox differs.")
            baseline_ids = {str(row["id"]) for row in baseline["before_import_ids"]}
            require(len(baseline_ids) == baseline.get("enumerated_count") == BASELINE_COUNT, "Baseline denominator differs.")
            pilot = m.load_json(HERE / "pilot-content-verification.json")
            pilot_ids = {row["gmail_message_id"] for row in pilot.get("rows", [])}
            require(pilot.get("ok") is True and pilot.get("passed_count") == pilot.get("checked_count") == 5 and len(pilot_ids) == 5 and pilot_ids <= receipts, "Five-message pilot fidelity evidence is invalid.")
            manual_evidence = []
            if manual_evidence_path in protected:
                manual_evidence.append(validate_manual_readback(m.load_json(manual_evidence_path), manifest_by_key, checkpoint["states"]))
            report["manual_raw_readback_evidence"] = manual_evidence
            automatic_evidence = [validate_automatic_raw_readback(m.load_json(path), path, manifest_by_key,
                                  checkpoint["states"]) for path in automatic_evidence_paths]
            report["automatic_raw_readback_evidence"] = automatic_evidence
            audited_ids = (pilot_ids | {entry["gmail_message_id"] for entry in manual_evidence}
                           | {entry["gmail_message_id"] for entry in automatic_evidence})
            report["raw_mime_fidelity_scope"] = {
                "pilot_verified_sample_count": 5,
                "manual_raw_audit_exception_count": len(manual_evidence),
                "automatic_raw_header_comparison_count": len(automatic_evidence),
                "verified_distinct_message_count": len(audited_ids),
                "full_run_raw_comparison": False,
            }

            report["stage"] = "gmail_id_presence"
            _, service, _ = m.load_authorized_credentials(profile)
            report["exact_account_guard_passed"] = True
            live_ids, pages = list_all_gmail_ids(service)
            missing_receipts = sorted(receipts - live_ids)
            missing_baseline = sorted(baseline_ids - live_ids)
            report["gmail_presence"] = {
                "include_spam_trash": True, "all_pages_enumerated": True, "pages": pages,
                "live_id_count": len(live_ids), "live_ids": sorted(live_ids),
                "migration_receipt_count": len(receipts), "migration_receipt_ids": sorted(receipts),
                "missing_migration_receipt_ids": missing_receipts,
                "baseline_id_count": len(baseline_ids), "missing_baseline_ids": missing_baseline,
                "baseline_receipt_overlap_count": len(baseline_ids & receipts),
                "additional_unowned_id_count": len(live_ids - baseline_ids - receipts),
                "additional_unowned_ids": sorted(live_ids - baseline_ids - receipts),
            }
            require(not missing_receipts and not missing_baseline, "A migration receipt or baseline ID is absent.")
            report["stage"] = "final_local_integrity"
            require(all(m.sha256_file(path) == fingerprint for path, fingerprint in protected_hashes.items()), "Protected local evidence changed during verification.")
            report["protected_files_unchanged"] = True
            report["ok"] = True
            report["stage"] = "verified"
    except Exception as exc:
        report["error_type"] = type(exc).__name__
        if isinstance(exc, m.MigrationError):
            report["error"] = str(exc)
        report["ok"] = False
    m.write_json_atomic(OUTPUT, report)
    RESULT.write_text(run_result_text(report), encoding="utf-8")
    print(json.dumps({"ok": report["ok"], "stage": report["stage"], "source_rows": report.get("sources", {}).get("union_rows"), "receipts_present": not report.get("gmail_presence", {}).get("missing_migration_receipt_ids", ["not_checked"]), "baseline_present": not report.get("gmail_presence", {}).get("missing_baseline_ids", ["not_checked"])}))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit("Archived reference variant. Use the configurable v2 engine at the repository root.")
    raise SystemExit(main())
