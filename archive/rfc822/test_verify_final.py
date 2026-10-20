# Sanitized historical reference: source-specific evidence and live configuration are not distributed.
"""Offline integrity/gating regressions; no credentials, source writes, or Gmail calls."""
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

import finish_when_done as supervisor
import verify_final as verifier


class FinalVerifierTests(unittest.TestCase):
    def test_incomplete_report_stops_before_authentication_or_source_reads(self):
        profile = SimpleNamespace(report_path=Path("unused"))
        with mock.patch.object(verifier.m, "load_json", return_value={"complete": False}), \
             mock.patch.object(verifier.m, "load_authorized_credentials") as auth, \
             mock.patch.object(verifier.m, "load_manifest") as manifest:
            with self.assertRaises(verifier.m.MigrationError):
                verifier.verify_locked(profile, {})
            auth.assert_not_called()
            manifest.assert_not_called()

    def test_readonly_lock_preserves_inode_contents_and_excludes_another_holder(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "lock"
            path.write_bytes(b"existing runner evidence\n")
            with verifier.readonly_lock(path):
                with self.assertRaises(verifier.m.MigrationError):
                    with verifier.readonly_lock(path):
                        self.fail("Concurrent lock admitted")
            self.assertEqual(path.read_bytes(), b"existing runner evidence\n")
            with verifier.readonly_lock(path):
                pass

    def test_inventory_detects_missing_baseline_receipts_and_new_custom_label(self):
        before = {"destination": verifier.MAILBOX,
                  "gmail_profile": {"emailAddress": verifier.MAILBOX},
                  "messages": [{"id": name} for name in ("a", "b", "c")],
                  "labels": {"labels": [{"id": "INBOX", "type": "system"}]}}
        result = verifier.baseline_checks(before, {"a", "b", "r1", "new-delivery"},
                     [{"id": "INBOX", "type": "system"}, {"id": "Label_1", "type": "user"}],
                     {"r1", "r2"})
        self.assertEqual(result["missing_baseline_ids"], ["c"])
        self.assertEqual(result["missing_receipt_ids"], ["r2"])
        self.assertEqual(result["new_custom_label_ids"], ["Label_1"])
        self.assertEqual(result["additional_ids_not_baseline_or_receipts"], ["new-delivery"])

    def test_inventory_pages_are_bounded_and_repetition_rejected(self):
        for pages in (
            [{"messages": [{"id": "a"}], "nextPageToken": "next"},
             {"messages": [{"id": "a"}]}],
            [{"messages": [{"id": "a"}], "nextPageToken": "next"},
             {"messages": [{"id": "b"}], "nextPageToken": "next"}],
        ):
            with self.subTest(pages=pages), mock.patch.object(verifier.m, "execute_idempotent", side_effect=pages):
                with self.assertRaises(verifier.m.MigrationError):
                    verifier.list_all_gmail_ids(mock.Mock())
        with mock.patch.object(verifier, "MAX_INVENTORY_PAGES", 1), \
             mock.patch.object(verifier.m, "execute_idempotent", return_value={"nextPageToken": "more"}) as request:
            with self.assertRaises(verifier.m.MigrationError):
                verifier.list_all_gmail_ids(mock.Mock())
            self.assertEqual(request.call_count, 1)

    def test_successful_inventory_keeps_all_ids(self):
        with mock.patch.object(verifier.m, "execute_idempotent", side_effect=[
            {"messages": [{"id": "a"}], "nextPageToken": "next"}, {"messages": [{"id": "b"}]}
        ]):
            ids, pages = verifier.list_all_gmail_ids(mock.Mock())
            self.assertEqual(ids, {"a", "b"})
            self.assertEqual(pages, 2)

    def test_local_only_content_repair_makes_no_raw_request(self):
        row = {"source_sha256": verifier.CONTENT_REPAIR_SOURCE_SHA256, "item_key": "source625"}
        with mock.patch.object(verifier.m, "execute_idempotent") as request:
            result = verifier.verify_content_repair(mock.Mock(), mock.Mock(), row, {"status": "local_only_reviewed"})
            self.assertEqual(result["status"], "preserved_local_only")
            self.assertEqual(result["gmail_reads"], 0)
            request.assert_not_called()

    def test_completed_report_cannot_hide_manual_exemption_or_replacement(self):
        profile = SimpleNamespace(source_root=verifier.SOURCE_ROOT, custom_label_policy="none")
        manifest = {"messages": [{}] * verifier.SOURCE_COUNT}
        final = {"complete": True, "accounted_complete": True, "final_reconciliation_verified": True,
                 "final_reconciliation_failure_rows": [], "unresolved_extra_candidate_rows": []}
        for state in ({"status": "verified_manual"}, {"status": "verified", "replacement": {"path": "x"}}):
            with self.subTest(state=state), mock.patch.object(verifier.m, "build_report", return_value=final):
                with self.assertRaises(verifier.m.MigrationError):
                    verifier.validate_completion(profile, manifest, {"states": {"a": state}}, final)

    def test_supervisor_never_retries_nonzero_import_and_sets_exact_allowlist_flag(self):
        profile = SimpleNamespace(path=Path("profile.json"), source_mailbox=supervisor.MAILBOX,
                                  destination=supervisor.MAILBOX)
        statuses = []
        with mock.patch.object(supervisor, "supervisor_lock", return_value=nullcontext()), \
             mock.patch.object(supervisor.m, "load_profile", return_value=profile), \
             mock.patch.object(supervisor, "check_pilot"), \
             mock.patch.object(supervisor, "launch_once", return_value=2) as launch, \
             mock.patch.object(supervisor, "save", side_effect=lambda status: statuses.append(dict(status))), \
             mock.patch.object(supervisor.m, "load_json") as reads:
            self.assertEqual(supervisor.main(["--run-import"]), 2)
        self.assertEqual(launch.call_count, 1)
        command = launch.call_args.args[0]
        self.assertIn("--continue-known-security-rejections-local-only", command)
        self.assertEqual(command[command.index("--confirm-destination") + 1], supervisor.MAILBOX)
        self.assertEqual(command[command.index("--confirm-source-count") + 1], "951")
        self.assertEqual(statuses[-1]["automatic_write_retries"], 0)
        self.assertEqual(statuses[-1]["phase"], "needs_review")
        reads.assert_not_called()

    def test_stale_pilot_receipt_does_not_authorize_full_import(self):
        rows = [{"item_key": str(i), "gmail_message_id": str(i), "prepared_sha256": str(i), "ok": True}
                for i in range(5)]
        pilot = {"ok": True, "destination": supervisor.MAILBOX, "checked_count": 5,
                 "passed_count": 5, "rows": rows}
        states = {str(i): {"status": "verified", "gmail_message_id": str(i),
                          "verified_prepared_sha256": str(i)} for i in range(5)}
        states["3"]["gmail_message_id"] = "changed"
        with mock.patch.object(supervisor.m, "load_json", return_value=pilot), \
             mock.patch.object(supervisor.m, "load_manifest", return_value={}), \
             mock.patch.object(supervisor.m, "load_checkpoint", return_value={"states": states}):
            with self.assertRaises(supervisor.m.MigrationError):
                supervisor.check_pilot(mock.Mock())


if __name__ == "__main__":
    raise SystemExit("Archived reference variant. Use the configurable v2 engine at the repository root.")
    unittest.main()
