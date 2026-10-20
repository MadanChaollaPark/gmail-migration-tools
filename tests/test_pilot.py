"""Offline preflight and write-boundary tests using fictional EML messages."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

MODULE = Path(__file__).resolve().parents[1] / "pilot/gmail_eml_pilot.py"
spec = importlib.util.spec_from_file_location("pilot", MODULE)
pilot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pilot)


class PilotBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "Inbox"
        self.source.mkdir()
        self.credentials = self.root / "oauth.json"
        self.credentials.write_text(json.dumps({"installed": {"client_id": "fictional.apps.googleusercontent.com"}}))
        rows = []
        for index in range(5):
            path = self.source / f"{index}.eml"
            raw = (
                f"Message-ID: <pilot-{index}@example.org>\r\n"
                "Date: Tue, 20 Oct 2026 09:00:00 +0000\r\n"
                "From: sender@example.org\r\nTo: person@example.org\r\n"
                "Delivered-To: person@example.org\r\n"
                f"Subject: Fictional pilot {index}\r\n\r\nFixture {index}\r\n"
            ).encode()
            path.write_bytes(raw)
            message_id, date, timestamp = pilot.parse_message_identity(path, "person@example.org")
            rows.append({
                "pilot_id": f"pilot-{index}", "relative_path": path.name,
                "size_bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                "rfc822_message_id": message_id, "date_header": date,
                "expected_internal_date_ms": timestamp, "gmail_label_ids": ["INBOX"],
            })
        self.manifest = {
            "expected_destination": "person@example.org", "source_mailbox": "person@example.org",
            "planned_count": 5, "messages": rows, "source_root": str(self.source),
            "expected_source_folder": "Inbox", "source_eml_count": 5,
            "source_total_bytes": sum(row["size_bytes"] for row in rows),
            "oauth_client_id": "fictional.apps.googleusercontent.com",
            "expected_checkpoint": str(self.root / "checkpoint.json"),
        }

    def test_fictional_frozen_manifest_passes_without_changing_source(self):
        before = {p.name: p.read_bytes() for p in self.source.iterdir()}
        destination, _, rows = pilot.validate_manifest(self.manifest, self.credentials)
        self.assertEqual(destination, "person@example.org")
        self.assertEqual(len(rows), 5)
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.source.iterdir()})

    def test_source_mutation_is_rejected(self):
        (self.source / "0.eml").write_bytes(b"changed")
        with self.assertRaises(pilot.PreflightError):
            pilot.validate_manifest(self.manifest, self.credentials)

    def test_wrong_oauth_client_is_rejected(self):
        self.credentials.write_text(json.dumps({"installed": {"client_id": "other.apps.googleusercontent.com"}}))
        with self.assertRaises(pilot.PreflightError):
            pilot.validate_manifest(self.manifest, self.credentials)

    def test_invalid_destination_is_rejected(self):
        self.manifest["expected_destination"] = "not-an-address"
        with self.assertRaises(pilot.PreflightError):
            pilot.validate_manifest(self.manifest, self.credentials)

    def run_cli(self, extra):
        manifest_path = self.root / "manifest.json"
        manifest_path.write_text(json.dumps(self.manifest))
        argv = ["pilot", "--manifest", str(manifest_path), "--credentials", str(self.credentials),
                "--checkpoint", str(self.root / "checkpoint.json"), *extra]
        with patch.object(sys, "argv", argv), patch.object(pilot, "authorize") as authorize:
            result = pilot.main()
            authorize.assert_not_called()
        return result

    def test_default_preflight_never_authorizes(self):
        self.assertEqual(self.run_cli([]), 0)

    def test_unconfirmed_execution_never_authorizes(self):
        self.assertNotEqual(self.run_cli(["--execute", "--confirm-destination", "wrong@example.org"]), 0)


if __name__ == "__main__":
    unittest.main()
