# Sanitized historical reference: source-specific evidence and live configuration are not distributed.
"""Offline evidence-schema regression tests; no checkpoint or API writes."""

import copy
from types import SimpleNamespace
import unittest
from unittest import mock

import raw_header_runner as adapter


class UncertainEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.profile = SimpleNamespace(destination='example-a88c3515@example.org', source_mailbox='example-a88c3515@example.org')
        self.before = {
            "status": "inflight",
            "attempted_at": "2026-09-20T17:03:45+00:00",
            "attempted_prepared_sha256": "a" * 64,
            "baseline_unknown_gmail_ids": [],
        }
        self.checkpoint = {"states": {"fixture-key": copy.deepcopy(self.before)}}
        self.timeout = {
            "status": "uncertain", "http_status": 0,
            "google_error": "The read operation timed out",
            "google_error_fingerprint": "b" * 64,
            "google_error_reasons": [],
        }

    def capture(self, updates):
        before_checkpoint = copy.deepcopy(self.checkpoint)
        before_updates = copy.deepcopy(updates)
        with mock.patch.object(adapter, "_original_save_state") as original:
            adapter.save_state(self.profile, self.checkpoint, "fixture-key", **updates)
        original.assert_called_once()
        self.assertEqual(original.call_args.args, (self.profile, self.checkpoint, "fixture-key"))
        self.assertEqual(self.checkpoint, before_checkpoint)
        self.assertEqual(updates, before_updates)
        return original.call_args.kwargs

    def test_timeout_adds_only_actual_error_and_preserves_ambiguity(self):
        passed = self.capture(self.timeout)
        self.assertEqual(passed, {**self.timeout, "error": self.timeout["google_error"]})
        merged = {**self.before, **passed}
        self.assertEqual(merged["status"], "uncertain")
        self.assertEqual(merged["http_status"], 0)
        self.assertEqual(merged["attempted_prepared_sha256"], self.before["attempted_prepared_sha256"])
        self.assertNotIn("gmail_message_id", merged)
        self.assertTrue(any(merged.get(field) for field in ("error", "error_type", "reconciliation_observations", "http_status")))

    def test_merged_existing_evidence_is_considered(self):
        self.checkpoint["states"]["fixture-key"].update(self.timeout)
        passed = self.capture({"decision_reason": "fixture only"})
        self.assertEqual(passed, {"decision_reason": "fixture only", "error": self.timeout["google_error"]})

    def test_recognized_existing_or_new_evidence_remains_untouched(self):
        for field, value in (
            ("error", "preserve existing uncertainty description"),
            ("error_type", "TimeoutError"),
            ("reconciliation_observations", [{"match_ids": []}]),
            ("http_status", 503),
        ):
            with self.subTest(field=field, location="updates"):
                updates = {**self.timeout, field: value}
                self.assertEqual(self.capture(updates), updates)
            with self.subTest(field=field, location="existing"):
                self.checkpoint["states"]["fixture-key"][field] = value
                updates = {key: item for key, item in self.timeout.items() if key != field}
                self.assertEqual(self.capture(updates), updates)
                self.checkpoint["states"]["fixture-key"].pop(field)

    def test_no_fabricated_error_without_both_message_and_fingerprint(self):
        for changes in ({"google_error": ""}, {"google_error": None}, {"google_error": "   "}, {"google_error_fingerprint": ""}):
            with self.subTest(changes=changes):
                updates = {**self.timeout, **changes}
                self.assertEqual(self.capture(updates), updates)

    def test_other_statuses_and_mailboxes_are_not_changed(self):
        for status in ("pending", "review_required", "verified", "google_rejected"):
            with self.subTest(status=status):
                updates = {**self.timeout, "status": status}
                self.assertEqual(self.capture(updates), updates)
        self.profile.destination = self.profile.source_mailbox = "other@example.org"
        self.assertEqual(self.capture(self.timeout), self.timeout)

    def test_original_failure_propagates_without_retry(self):
        with mock.patch.object(adapter, "_original_save_state", side_effect=adapter.engine.MigrationError("fixture disk failure")) as original:
            with self.assertRaises(adapter.engine.MigrationError):
                adapter.save_state(self.profile, self.checkpoint, "fixture-key", **self.timeout)
            original.assert_called_once()


if __name__ == "__main__":
    raise SystemExit("Archived reference variant. Use the configurable v2 engine at the repository root.")
    unittest.main()
