# Sanitized historical reference: source-specific evidence and live configuration are not distributed.
"""Safety checks for the exact-fingerprint source 625 repair."""
import base64
import importlib.util
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest.mock import patch

import preparation_repairs as repairs

SOURCE_ROOT = Path('/private/migration-example/source-export')
ENGINE_PATH = next(p / "gmail_eml_migration_v2.py" for p in Path(__file__).resolve().parents if (p / "gmail_eml_migration_v2.py").is_file())
spec = importlib.util.spec_from_file_location("_repair_test_engine", ENGINE_PATH)
engine = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = engine
spec.loader.exec_module(engine)


class PreparationRepairsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = next(SOURCE_ROOT.glob("625.*")).read_bytes()

    def test_exact_repair_preserves_all_outside_bytes_and_decoded_attachment(self):
        prepared, names, counts, old_defects = repairs.prepare_source_bytes(
            self.raw, engine.prepare_source_bytes
        )
        self.assertEqual(repairs.sha256(prepared), repairs.PREPARED_SHA256)
        self.assertEqual(names, [repairs.REPAIR_NAME])
        self.assertEqual(counts, {repairs.REPAIR_NAME: 1})
        self.assertEqual(old_defects, repairs.SOURCE_DEFECTS)
        c0, c1 = repairs.CTE_RANGE
        p0, p1 = repairs.PAYLOAD_RANGE
        delta = len(repairs.NEW_CTE) - len(repairs.OLD_CTE)
        decoded = base64.b64decode(re.sub(rb"\s", b"", self.raw[p0:p1]), validate=True)
        self.assertEqual(prepared[:c0], self.raw[:c0])
        self.assertEqual(prepared[c0 + len(repairs.NEW_CTE):p0 + delta], self.raw[c1:p0])
        self.assertEqual(prepared[p0 + delta:p0 + delta + len(decoded)], decoded)
        self.assertEqual(prepared[p0 + delta + len(decoded):], self.raw[p1:])
        self.assertEqual(repairs.sha256(decoded), repairs.ATTACHMENT_SHA256)
        self.assertEqual(engine.prepare_source_bytes(prepared), (prepared, [], {}, []))

    def test_near_miss_does_not_receive_repair(self):
        changed = self.raw + b" "
        self.assertIsNone(repairs.repair_exact_source(changed))
        with self.assertRaises(engine.MigrationError):
            repairs.prepare_source_bytes(changed, engine.prepare_source_bytes)

    def test_same_defect_different_content_is_rejected(self):
        changed = self.raw.replace(b"X-Spamfilter-Score:", b"X-Spamfilter-Other:", 1)
        self.assertNotEqual(changed, self.raw)
        self.assertIsNone(repairs.repair_exact_source(changed))
        with self.assertRaises(engine.MigrationError):
            repairs.prepare_source_bytes(changed, engine.prepare_source_bytes)

    def test_valid_unrelated_source_is_unchanged(self):
        valid = b"From: a@example.com\r\nDate: Mon, 21 Sep 2026 00:00:00 +0000\r\n\r\nBody\r\n"
        self.assertEqual(repairs.prepare_source_bytes(valid, engine.prepare_source_bytes),
                         (valid, [], {}, []))


class DuplicateDeliveryRepairTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = next(SOURCE_ROOT.glob("805.*")).read_bytes()
        cls.canonical = next(SOURCE_ROOT.glob("804.*")).read_bytes()

    def test_exact_duplicate_becomes_byte_exact_canonical(self):
        actual = repairs.prepare_source_bytes(self.raw, engine.prepare_source_bytes)
        self.assertEqual(actual, (self.canonical, [repairs.DUPLICATE_REPAIR_NAME],
                                  {repairs.DUPLICATE_REPAIR_NAME: 1}, []))
        repairs.validate_duplicate_content_equivalence(self.raw, self.canonical)

    def test_changed_source_is_not_canonicalized(self):
        changed = self.raw + b" "
        self.assertIsNone(repairs.canonicalize_exact_duplicate(changed))
        self.assertEqual(repairs.prepare_source_bytes(changed, engine.prepare_source_bytes),
                         (changed, [], {}, []))

    def test_missing_canonical_source_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(repairs, "CANONICAL_SOURCE_PATH", Path(directory) / "missing.eml"):
                with self.assertRaises(FileNotFoundError):
                    repairs.canonicalize_exact_duplicate(self.raw)

    def test_changed_canonical_source_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "804.eml"
            path.write_bytes(self.canonical + b" ")
            with patch.object(repairs, "CANONICAL_SOURCE_PATH", path):
                with self.assertRaisesRegex(ValueError, "canonical source 804 hash"):
                    repairs.canonicalize_exact_duplicate(self.raw)

    def test_body_difference_is_rejected_by_content_guard(self):
        with self.assertRaisesRegex(ValueError, "MIME body differs"):
            repairs.validate_duplicate_content_equivalence(self.raw + b" ", self.canonical)

    def test_authored_header_difference_is_rejected_by_content_guard(self):
        changed = self.raw.replace(b"\r\nSubject:", b"\r\nSubject: Changed", 1)
        self.assertNotEqual(changed, self.raw)
        with self.assertRaisesRegex(ValueError, "protected raw headers differ"):
            repairs.validate_duplicate_content_equivalence(changed, self.canonical)


if __name__ == "__main__":
    raise SystemExit("Archived reference variant. Use the configurable v2 engine at the repository root.")
    unittest.main()
