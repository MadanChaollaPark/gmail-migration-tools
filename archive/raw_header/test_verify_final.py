# Sanitized historical reference: source-specific evidence and live configuration are not distributed.
"""Offline safety tests; no actual migration evidence or Gmail is accessed."""

from contextlib import nullcontext, redirect_stdout
import fcntl
import io
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import verify_final as verifier


class FinalVerificationTests(unittest.TestCase):
    def test_read_only_lock_preserves_file_and_rejects_active_owner(self):
        with tempfile.TemporaryDirectory() as directory:
            checkpoint = Path(directory) / "checkpoint.json"
            lock = Path(directory) / "checkpoint.json.lock"
            content = b"existing runner lock record\n"
            lock.write_bytes(content)
            with lock.open("rb") as owner:
                fcntl.flock(owner.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                with self.assertRaises(verifier.m.MigrationError):
                    with verifier.read_only_checkpoint_lock(checkpoint):
                        self.fail("contended lock was acquired")
                fcntl.flock(owner.fileno(), fcntl.LOCK_UN)
            with verifier.read_only_checkpoint_lock(checkpoint):
                self.assertEqual(lock.read_bytes(), content)
            self.assertEqual(lock.read_bytes(), content)

    def test_enumeration_consumes_every_page_and_includes_spam_trash(self):
        service = mock.Mock()
        listing = service.users.return_value.messages.return_value.list
        with mock.patch.object(verifier.m, "execute_idempotent", side_effect=lambda factory: factory().execute()) as execute:
            listing.return_value.execute.side_effect = [
                {"messages": [{"id": "a"}], "nextPageToken": "next"},
                {"messages": [{"id": "b"}]},
            ]
            ids, pages = verifier.list_all_gmail_ids(service)
        self.assertEqual(ids, {"a", "b"})
        self.assertEqual(pages, 2)
        self.assertEqual(execute.call_count, 2)
        for call in listing.call_args_list:
            self.assertTrue(call.kwargs["includeSpamTrash"])
        self.assertEqual(listing.call_args_list[1].kwargs["pageToken"], "next")

    def test_repeated_pagination_token_fails(self):
        with mock.patch.object(verifier.m, "execute_idempotent", return_value={"nextPageToken": "same"}):
            with self.assertRaises(verifier.m.MigrationError):
                verifier.list_all_gmail_ids(mock.Mock())

    def test_incomplete_engine_report_blocks_before_credentials_and_hashing(self):
        profile = SimpleNamespace(destination=verifier.MAILBOX, source_mailbox=verifier.MAILBOX, checkpoint_path=Path("fixture-checkpoint"), report_path=Path("fixture-report"))
        with mock.patch.object(verifier.m, "load_profile", return_value=profile), \
             mock.patch.object(verifier, "read_only_checkpoint_lock", return_value=nullcontext()), \
             mock.patch.object(verifier.m, "load_manifest", return_value={}), \
             mock.patch.object(verifier.m, "load_checkpoint", return_value={}), \
             mock.patch.object(verifier.m, "load_json", return_value={"complete": False}), \
             mock.patch.object(verifier.m, "build_report", return_value={"complete": False}), \
             mock.patch.object(verifier.m, "load_authorized_credentials") as credentials, \
             mock.patch.object(verifier, "audit_sources") as sources, \
             mock.patch.object(verifier.m, "write_json_atomic") as write_report, \
             mock.patch.object(verifier, "RESULT") as result, redirect_stdout(io.StringIO()):
            self.assertEqual(verifier.main(), 1)
            credentials.assert_not_called()
            sources.assert_not_called()
            self.assertFalse(write_report.call_args.args[1]["ok"])
            self.assertIn("incomplete", result.write_text.call_args.args[0])


if __name__ == "__main__":
    raise SystemExit("Archived reference variant. Use the configurable v2 engine at the repository root.")
    unittest.main()
