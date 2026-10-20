# Sanitized historical reference: source-specific evidence and live configuration are not distributed.
"""Offline regression tests; no profile, checkpoint, credential or API access."""

from __future__ import annotations

import hashlib
from pathlib import Path
import unittest
from unittest import mock

import raw_header_runner as adapter


ROOT = Path(__file__).resolve().parent / "source-union"
UNSAFE_ID_SHA = '000000000000000000000000000000000000000000000000000000000000865a'
engine = adapter.engine


def parse(raw):
    return engine.BytesParser(policy=engine.policy.default).parsebytes(raw)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def semantic_parts(message, excluded_header):
    return [
        {
            "headers": [
                (name, str(value))
                for name, value in part.raw_items()
                if not excluded_header(index, name)
            ],
            "type": part.get_content_type(),
            "boundary": part.get_boundary(),
            "preamble": part.preamble,
            "epilogue": part.epilogue,
            "raw_payload": None if part.is_multipart() else part.get_payload(),
            "decoded_payload": None if part.is_multipart() else part.get_payload(decode=True),
        }
        for index, part in enumerate(message.walk())
    ]


class SourceRepairTests(unittest.TestCase):
    def setUp(self):
        self.source_paths = [
            ROOT / (adapter.AUDITED_SOURCE_SHA256 + ".eml"),
            ROOT / (UNSAFE_ID_SHA + ".eml"),
        ]
        self.original_hashes = {path: sha(path.read_bytes()) for path in self.source_paths}

    def tearDown(self):
        for path, fingerprint in self.original_hashes.items():
            self.assertEqual(sha(path.read_bytes()), fingerprint)
            self.assertEqual(fingerprint, path.stem)

    def test_exact_container_repair_preserves_all_other_semantics(self):
        path = self.source_paths[0]
        raw = path.read_bytes()
        with self.assertRaises(engine.MigrationError):
            adapter._original_prepare_source_bytes(raw)
        prepared, row = engine.parse_source_path(path, ROOT)
        self.assertEqual(sha(prepared), adapter.AUDITED_PREPARED_SHA256)
        self.assertEqual(row["source_sha256"], adapter.AUDITED_SOURCE_SHA256)
        self.assertEqual(row["repairs"], [adapter.REPAIR_NAME])
        self.assertEqual(row["repair_occurrences"], {adapter.REPAIR_NAME: 2})
        self.assertEqual(row["source_parser_defects"], adapter.AUDITED_DEFECTS)
        self.assertEqual(engine.collect_defects(parse(prepared)), [])
        excluded = lambda index, name: index in (0, 1) and name.lower() == "content-transfer-encoding"
        self.assertEqual(semantic_parts(parse(raw), excluded), semantic_parts(parse(prepared), excluded))
        (s1, e1), (s2, e2) = adapter.AUDITED_RANGES
        self.assertEqual(prepared, raw[:s1] + raw[e1:s2] + raw[e2:])
        self.assertEqual(len(raw) - len(prepared), 90)

    def test_changed_source_does_not_receive_special_repair(self):
        raw = self.source_paths[0].read_bytes() + b"\r\n"
        with mock.patch.object(adapter, "_original_prepare_source_bytes", wraps=adapter._original_prepare_source_bytes) as original:
            with self.assertRaises(engine.MigrationError):
                adapter.prepare_source_bytes(raw)
            original.assert_called_once_with(raw)

    def test_ordinary_source_is_byte_exact(self):
        raw = b"From: a@example.org\r\nMessage-ID: <x@example.org>\r\nDate: Mon, 14 Sep 2026 12:00:00 +0000\r\nContent-Type: text/plain\r\n\r\nfixture\r\n"
        self.assertEqual(adapter.prepare_source_bytes(raw), (raw, [], {}, []))

    def test_bad_message_id_uses_existing_policy_only(self):
        path = self.source_paths[1]
        raw = path.read_bytes()
        self.assertEqual(adapter.prepare_source_bytes(raw), (raw, [], {}, []))
        with self.assertRaises(engine.MigrationError):
            engine.parse_source_path(path, ROOT)
        prepared, row = engine.parse_source_path(path, ROOT, "deterministic_sha256_upload_copy")
        self.assertEqual(row["repairs"], [engine.REPAIR_GENERATED_MESSAGE_ID])
        provenance = row["message_id_provenance"]
        self.assertEqual(provenance["source_header_state"], "invalid_single_header")
        self.assertEqual(provenance["source_header_count"], 1)
        self.assertEqual(row["message_id"], engine.deterministic_generated_message_id(UNSAFE_ID_SHA))
        excluded = lambda index, name: index == 0 and name.lower() == "message-id"
        self.assertEqual(semantic_parts(parse(raw), excluded), semantic_parts(parse(prepared), excluded))
        before_end, _ = engine.rfc_header_boundary(raw)
        after_end, _ = engine.rfc_header_boundary(prepared)
        self.assertEqual(raw[before_end:], prepared[after_end:])


class PilotTests(unittest.TestCase):
    def test_stops_before_next_call_after_verified_outcomes(self):
        original = mock.Mock(side_effect=["verified", "local_only", "verified"])
        limited = adapter.make_pilot_importer(original, 2)
        self.assertEqual(limited("a", flag=True), "verified")
        self.assertEqual(limited("b"), "local_only")
        self.assertEqual(limited("c"), "verified")
        with self.assertRaisesRegex(engine.MigrationError, "Pilot complete; resume same checkpoint"):
            limited("must-not-be-attempted")
        self.assertEqual(original.call_args_list, [mock.call("a", flag=True), mock.call("b"), mock.call("c")])

    def test_zero_limit_prevents_any_call(self):
        original = mock.Mock()
        with self.assertRaises(engine.MigrationError):
            adapter.make_pilot_importer(original, 0)(object())
        original.assert_not_called()

    def test_original_fail_closed_exception_passes_through(self):
        error = engine.AuthRequired("fixture account failure")
        original = mock.Mock(side_effect=error)
        with self.assertRaises(engine.AuthRequired) as raised:
            adapter.make_pilot_importer(original, 1)()
        self.assertIs(raised.exception, error)

    def test_invalid_environment_stops_before_engine_main(self):
        with mock.patch.dict(adapter.os.environ, {"SG_PILOT_LIMIT": "-1"}), mock.patch.object(engine, "main") as main, mock.patch("sys.stderr"):
            self.assertEqual(adapter.main([]), 2)
            main.assert_not_called()

    def test_unset_environment_retains_original_importer(self):
        with mock.patch.dict(adapter.os.environ, {}, clear=True), mock.patch.object(engine, "main", return_value=19) as main:
            self.assertEqual(adapter.main(["fixture"]), 19)
            self.assertIs(engine.import_one, adapter._original_import_one)
            main.assert_called_once_with(["fixture"])


if __name__ == "__main__":
    raise SystemExit("Archived reference variant. Use the configurable v2 engine at the repository root.")
    unittest.main()
