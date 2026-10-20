# Sanitized historical reference: source-specific evidence and live configuration are not distributed.
"""Offline adapter regression tests: temporary state only, no OAuth or Gmail."""

from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

import runner


def fixture_profile(**overrides):
    return SimpleNamespace(**{
        "source_mailbox": runner.EXPECTED_SOURCE_MAILBOX,
        "destination": runner.EXPECTED_DESTINATION,
        **overrides,
    })


class RunnerTests(unittest.TestCase):
    def test_pilot_stops_before_sixth_even_when_some_rows_are_local_only(self):
        original = mock.Mock(side_effect=["verified", "local_only", "verified", "verified", "verified"])
        bounded = runner.make_pilot_importer(original, 5)
        for _ in range(5):
            bounded("row")
        with self.assertRaises(runner.PilotComplete):
            bounded("sixth")
        self.assertEqual(original.call_count, 5)

    def test_zero_pilot_and_invalid_limits(self):
        original = mock.Mock()
        with self.assertRaises(runner.PilotComplete):
            runner.make_pilot_importer(original, 0)()
        original.assert_not_called()
        for bad in (-1, True, "5", 1.5):
            with self.subTest(bad=bad), self.assertRaises(runner.engine.MigrationError):
                runner.make_pilot_importer(original, bad)

    def test_destination_lock_excludes_different_profiles_for_same_mailbox_and_releases(self):
        first = fixture_profile(state_dir=Path("first-state"))
        second = fixture_profile(state_dir=Path("second-state"))
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(runner, "DESTINATION_LOCK_DIR", Path(directory)):
            with runner.destination_lock(first):
                with self.assertRaises(runner.engine.MigrationError):
                    with runner.destination_lock(second):
                        self.fail("Concurrent destination lock was admitted.")
            with runner.destination_lock(second):
                self.assertEqual(len(list(Path(directory).glob("*.lock"))), 1)

    def test_account_guard_rejects_either_identity_mismatch(self):
        runner.guard_profile(fixture_profile())
        for field in ("source_mailbox", "destination"):
            with self.subTest(field=field), self.assertRaises(runner.engine.MigrationError):
                runner.guard_profile(fixture_profile(**{field: 'example-a88c3515@example.org'}))

    def test_manual_readback_exemption_is_rejected(self):
        with mock.patch.object(runner, "_original_load_checkpoint", return_value={"states": {"key": {"status": "verified_manual"}}}):
            with self.assertRaises(runner.engine.MigrationError):
                runner.load_checkpoint(fixture_profile(), {})

    def test_uncertain_transport_error_roundtrips_through_real_checkpoint_loader(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = fixture_profile(
                migration_id='offline-rfc822-test', profile_fingerprint="a" * 64,
                manifest_path=root / "manifest.json", checkpoint_path=root / "checkpoint.json",
            )
            row = {
                "item_key": "c" * 64, "relative_path": "fixture.eml", "source_sha256": "d" * 64,
                "prepared_sha256": "e" * 64, "message_id": "<fixture@example.org>", "action": "import",
            }
            manifest = {"messages": [row]}
            runner.engine.write_json_atomic(profile.manifest_path, manifest)
            checkpoint = runner.engine.new_checkpoint(profile, manifest)
            runner.save_state(profile, checkpoint, row["item_key"],
                status="uncertain", http_status=0, google_error="The read operation timed out",
                google_error_fingerprint="f" * 64, attempted_prepared_sha256=row["prepared_sha256"])
            loaded = runner.load_checkpoint(profile, manifest)
            state = loaded["states"][row["item_key"]]
            self.assertEqual(state["status"], "uncertain")
            self.assertEqual(state["http_status"], 0)
            self.assertEqual(state["error"], "The read operation timed out")
            self.assertEqual(state["google_error_fingerprint"], "f" * 64)
            self.assertNotIn("gmail_message_id", state)

    def test_existing_uncertainty_evidence_is_not_overwritten(self):
        checkpoint = {"states": {"key": {"error": "Existing evidence"}}}
        updates = {"status": "uncertain", "http_status": 0,
                   "google_error": "Timeout", "google_error_fingerprint": "a" * 64}
        with mock.patch.object(runner, "_original_save_state") as original:
            runner.save_state(fixture_profile(), checkpoint, "key", **updates)
            self.assertEqual(original.call_args.kwargs, updates)

    def test_no_error_evidence_is_fabricated(self):
        for message, fingerprint in (("", "a" * 64), ("Timeout", "")):
            updates = {"status": "uncertain", "http_status": 0,
                       "google_error": message, "google_error_fingerprint": fingerprint}
            with self.subTest(message=message), mock.patch.object(runner, "_original_save_state") as original:
                runner.save_state(fixture_profile(), {"states": {"key": {}}}, "key", **updates)
                self.assertEqual(original.call_args.kwargs, updates)


if __name__ == "__main__":
    raise SystemExit("Archived reference variant. Use the configurable v2 engine at the repository root.")
    unittest.main()
