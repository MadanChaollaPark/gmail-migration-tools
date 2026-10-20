from __future__ import annotations

import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock


MODULE_PATH = next(p / "gmail_eml_migration_v2.py" for p in Path(__file__).resolve().parents if (p / "gmail_eml_migration_v2.py").is_file())
SPEC = importlib.util.spec_from_file_location("gmail_eml_migration_v2", MODULE_PATH)
assert SPEC and SPEC.loader
migration = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = migration
SPEC.loader.exec_module(migration)


def eml_bytes(index: int, folder: str = "Inbox") -> bytes:
    return (
        f"Message-ID: <message-{folder}-{index}@example.test>\r\n"
        f"Date: Fri, 18 Sep 2026 12:{index % 60:02d}:00 +0900\r\n"
        "From: sender@example.test\r\n"
        "To: person@example.test\r\n"
        f"Subject: migration row {index}\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "\r\n"
        f"body {index}\r\n"
    ).encode("utf-8")


def headerless_eml_bytes(index: int) -> bytes:
    raw = eml_bytes(index)
    return raw.split(b"\r\n", 1)[1]


def empty_boundaryless_placeholder_eml(nonempty: bool = False) -> bytes:
    body = b"payload\r\n" if nonempty else b""
    return (
        b"Message-ID: <broken-placeholder@example.test>\r\n"
        b"Date: Fri, 18 Sep 2026 12:00:00 +0900\r\n"
        b"From: sender@example.test\r\n"
        b"To: person@example.test\r\n"
        b"Subject: empty placeholder\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: multipart/mixed; boundary=\"=_webmail-test-0001\"\r\n"
        b"\r\n"
        b"--=_webmail-test-0001\r\n"
        b"Content-Type: multipart/related\r\n"
        b"Content-ID: <12345>\r\n"
        b"\r\n"
        b"Mime-Version: 1.0\r\n"
        b"\r\n"
        b"Content-Transfer-Encoding: 7bits\r\n"
        b"\r\n"
        b"\r\n"
        + body
        + b"--=_webmail-test-0001--\r\n"
    )


def returned_text_missing_separator_eml() -> bytes:
    return (
        b"Message-ID: <returned@example.test>\r\n"
        b"Date: Fri, 18 Sep 2026 12:00:00 +0900\r\n"
        b"From: postmaster@example.test\r\n"
        b"To: person@example.test\r\n"
        b"Subject: Returned mail\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: multipart/mixed; boundary=\"=_webmail-test-returned\"\r\n"
        b"\r\n"
        b"--=_webmail-test-returned\r\n"
        b"Content-Type: text/plain; charset=iso-8859-1\r\n"
        b"Content-Transfer-Encoding: 7bit\r\n"
        b"--\r\n"
        b"\r\n"
        b"--\r\n"
        b"--=_webmail-test-returned--\r\n"
    )


class FakeResponse:
    def __init__(self, status: int):
        self.status = status


class FakeHttpError(Exception):
    def __init__(self, status: int, reason: str, message: str):
        super().__init__(message)
        self.resp = FakeResponse(status)
        self.content = json.dumps(
            {
                "error": {
                    "message": message,
                    "errors": [{"reason": reason}],
                }
            }
        ).encode("utf-8")

    def _get_reason(self):
        return str(self)


class FakeRequest:
    def __init__(self, value):
        self.value = value

    def execute(self, num_retries=0):
        return self.value


class FakeUsers:
    def __init__(self, email):
        self.email = email

    def getProfile(self, userId):
        return FakeRequest({"emailAddress": self.email})


class FakeService:
    def __init__(self, email):
        self._users = FakeUsers(email)

    def users(self):
        return self._users


class MigrationV2Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.state = self.root / "state"
        self.source.mkdir()
        self.oauth = self.root / "oauth.json"
        self.oauth.write_text(
            json.dumps(
                {
                    "installed": {
                        "client_id": "client-id.apps.googleusercontent.com",
                        "client_secret": "test-only",
                        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                        "token_uri": "https://oauth2.googleapis.com/token",
                    }
                }
            ),
            encoding="utf-8",
        )
        self.profile_path = self.root / "profile.json"

    def tearDown(self):
        self.temp.cleanup()

    def write_profile(
        self,
        token_type="file",
        missing_message_id_policy="stop",
        custom_label_policy="archive_prefix_and_folder",
    ):
        token_store = (
            {"type": "file", "path": str(self.root / "token.json")}
            if token_type == "file"
            else {"type": "keychain", "service": "test.service"}
        )
        self.profile_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "migration_id": "test-mailbox",
                    "source_root": str(self.source),
                    "source_mailbox": "person@example.test",
                    "destination": "person@example.test",
                    "state_dir": str(self.state),
                    "oauth_client": str(self.oauth),
                    "label_prefix": "Cafe24 Archive/person@example.test/test",
                    "custom_label_policy": custom_label_policy,
                    "root_folder": "Inbox",
                    "inbox_folders": ["Inbox"],
                    "progress_every": 250,
                    "google_rejection_policy": "stop",
                    "missing_message_id_policy": missing_message_id_policy,
                    "token_store": token_store,
                }
            ),
            encoding="utf-8",
        )
        return migration.load_profile(self.profile_path)

    def prepare(self, count=1, nested=False):
        for index in range(count):
            if nested and index % 2:
                folder = self.source / "Sent" / "Custom"
                folder.mkdir(parents=True, exist_ok=True)
                path = folder / f"{index}.eml"
                marker = "Sent-Custom"
            else:
                path = self.source / f"{index}.eml"
                marker = "Inbox"
            path.write_bytes(eml_bytes(index, marker))
        profile = self.write_profile()
        with redirect_stdout(io.StringIO()):
            migration.command_prepare(profile, replace=False)
        return profile, migration.load_manifest(profile)

    def verified_evidence(self, row, label_map, gmail_message_id):
        return {
            "status": "verified",
            "gmail_message_id": gmail_message_id,
            "verified_at": migration.utc_now(),
            "verified_prepared_sha256": row["prepared_sha256"],
            "readback_issues": [],
            "returned_label_ids": migration.expected_label_ids_for_row(
                row, label_map
            ),
        }

    def fake_final_reconcile(
        self, profile, manifest, checkpoint, service, label_map
    ):
        checkpoint["gmail_labels"] = dict(label_map)
        for row in manifest["messages"]:
            state = checkpoint["states"][row["item_key"]]
            if state["status"] not in {
                "verified",
                "verified_manual",
                "preexisting_reviewed",
                "duplicate_source_reviewed",
            }:
                continue
            state["final_readback_verified_at"] = migration.utc_now()
            if state["status"] != "duplicate_source_reviewed":
                state["final_readback_label_ids"] = list(
                    state.get("returned_label_ids", [])
                )
        checkpoint["final_reconciliation"] = {
            "checked_at": migration.utc_now(),
            "status": "verified",
        }
        migration.save_checkpoint(profile, checkpoint)
        return True

    def exact_duplicate_checkpoint_with_final_failure(self, failure):
        raw = eml_bytes(45, "shared")
        (self.source / "0.eml").write_bytes(raw)
        sent = self.source / "Sent"
        sent.mkdir()
        (sent / "1.eml").write_bytes(raw)
        profile = self.write_profile()
        with redirect_stdout(io.StringIO()):
            migration.command_prepare(profile, replace=False)
        manifest = migration.load_manifest(profile)
        canonical = next(
            row for row in manifest["messages"] if row["action"] == "import"
        )
        duplicate = next(
            row
            for row in manifest["messages"]
            if row["action"] == "merge_exact_duplicate"
        )
        label_map = {
            name: f"Label_{index}"
            for index, name in enumerate(
                canonical["target_label_names"], start=1
            )
        }
        checkpoint = migration.new_checkpoint(profile, manifest)
        checkpoint["gmail_labels"] = dict(label_map)
        canonical_state = checkpoint["states"][canonical["item_key"]]
        canonical_state.update(
            **self.verified_evidence(
                canonical, label_map, "gmail-canonical-final-failure"
            ),
            final_readback_verified_at=migration.utc_now(),
            final_readback_label_ids=migration.expected_label_ids_for_row(
                canonical, label_map
            ),
            final_reconciliation_failure=dict(failure),
        )
        duplicate_state = checkpoint["states"][duplicate["item_key"]]
        duplicate_state.update(
            status="duplicate_source_reviewed",
            represented_by_item_key=canonical["item_key"],
            represented_by_gmail_id="gmail-canonical-final-failure",
            represented_prepared_sha256=duplicate["prepared_sha256"],
            canonical_union_label_ids=migration.expected_label_ids_for_row(
                canonical, label_map
            ),
            verified_at=migration.utc_now(),
            decision="merge_exact_prepared_copy_into_canonical_gmail_message",
            decision_reason="Canonical initially verified with union labels",
            source_preserved=True,
            final_reconciliation_failure={
                "checked_at": migration.utc_now(),
                "issues": ["canonical final readback failed"],
            },
        )
        checkpoint["final_reconciliation"] = {
            "checked_at": migration.utc_now(),
            "status": "blocked",
        }
        migration.save_checkpoint(profile, checkpoint)
        migration.load_checkpoint(profile, manifest)
        return profile, manifest, canonical, duplicate

    def test_prepare_includes_more_than_250_and_all_folders(self):
        profile, manifest = self.prepare(count=251, nested=True)
        self.assertEqual(manifest["source_eml_count"], 251)
        self.assertEqual(sum(manifest["folder_counts"].values()), 251)
        self.assertIn("Inbox", manifest["folder_counts"])
        self.assertIn("Sent/Custom", manifest["folder_counts"])
        nested = next(
            row for row in manifest["messages"] if row["source_folder"] == "Sent/Custom"
        )
        self.assertEqual(nested["target_system_label_ids"], [])
        self.assertIn(
            f"{profile.label_prefix}/Sent/Custom", nested["target_label_names"]
        )

    def test_no_custom_label_policy_keeps_only_system_folder_labels(self):
        (self.source / "0.eml").write_bytes(eml_bytes(0))
        profile = self.write_profile(custom_label_policy="none")
        with redirect_stdout(io.StringIO()):
            migration.command_prepare(profile, replace=False)
        manifest = migration.load_manifest(profile)
        row = manifest["messages"][0]
        self.assertEqual(row["target_label_names"], [])
        self.assertEqual(row["target_system_label_ids"], ["INBOX"])
        checkpoint = migration.new_checkpoint(profile, manifest)
        service = mock.Mock()
        service.users.return_value.labels.return_value.list.return_value.execute.return_value = {
            "labels": []
        }
        with mock.patch.object(migration, "save_checkpoint"):
            self.assertEqual(
                migration.ensure_gmail_labels(
                    profile, manifest, checkpoint, service
                ),
                {},
            )
        service.users.return_value.labels.return_value.create.assert_not_called()

    def test_missing_message_id_requires_explicit_policy_and_preserves_source(self):
        source_path = self.source / "notice.eml"
        raw = headerless_eml_bytes(7)
        source_path.write_bytes(raw)
        strict_profile = self.write_profile()
        with self.assertRaisesRegex(
            migration.MigrationError, "lacks a safe Message-ID"
        ):
            migration.command_prepare(strict_profile, replace=False)
        self.assertFalse(strict_profile.manifest_path.exists())
        self.assertEqual(source_path.read_bytes(), raw)

        profile = self.write_profile(
            missing_message_id_policy="deterministic_sha256_upload_copy"
        )
        with redirect_stdout(io.StringIO()):
            migration.command_prepare(profile, replace=False)
        manifest = migration.load_manifest(profile)
        row = manifest["messages"][0]
        expected_id = migration.deterministic_generated_message_id(
            migration.sha256_bytes(raw)
        )
        self.assertEqual(row["message_id"], expected_id)
        self.assertEqual(
            row["message_id_provenance"]["kind"],
            "deterministic_sha256_upload_copy",
        )
        self.assertEqual(
            row["repairs"], [migration.REPAIR_GENERATED_MESSAGE_ID]
        )
        self.assertEqual(source_path.read_bytes(), raw)
        migration.validate_source_snapshot(profile, manifest)
        checkpoint = migration.new_checkpoint(profile, manifest)
        prepared, observed = migration.source_bytes_for_state(
            profile, row, checkpoint["states"][row["item_key"]]
        )
        self.assertIn(
            ("Message-ID: " + expected_id).encode("ascii"),
            prepared.split(b"\r\n\r\n", 1)[0],
        )
        self.assertEqual(observed["prepared_sha256"], row["prepared_sha256"])
        report = migration.build_report(profile, manifest, None)
        self.assertEqual(report["transformed_upload_count"], 1)
        self.assertEqual(report["generated_message_id_source_rows"], 1)

    def test_identical_headerless_sources_merge_and_prepare_is_stable(self):
        raw = headerless_eml_bytes(8)
        (self.source / "notice.eml").write_bytes(raw)
        sent = self.source / "Sent"
        sent.mkdir()
        (sent / "notice-copy.eml").write_bytes(raw)
        profile = self.write_profile(
            missing_message_id_policy="deterministic_sha256_upload_copy"
        )
        with redirect_stdout(io.StringIO()):
            migration.command_prepare(profile, replace=False)
        first = migration.load_manifest(profile)
        first_rows = {
            row["relative_path"]: (row["message_id"], row["prepared_sha256"])
            for row in first["messages"]
        }
        self.assertEqual(first["source_eml_count"], 2)
        self.assertEqual(first["unique_gmail_upload_rows"], 1)
        self.assertEqual(first["exact_prepared_duplicate_source_rows"], 1)
        self.assertEqual(len({row["message_id"] for row in first["messages"]}), 1)

        with redirect_stdout(io.StringIO()):
            migration.command_prepare(profile, replace=True)
        second = migration.load_manifest(profile)
        second_rows = {
            row["relative_path"]: (row["message_id"], row["prepared_sha256"])
            for row in second["messages"]
        }
        self.assertEqual(first_rows, second_rows)

    def test_invalid_single_message_id_is_replaced_only_in_upload_copy(self):
        invalid_values = (
            "<malformed@mail.example.test_extra@mail.example.test>",
            "<B[20-25",
            "<B202506121731494520803L5>",
        )
        for index, invalid_value in enumerate(invalid_values, start=1):
            with self.subTest(invalid_value=invalid_value):
                raw = eml_bytes(index).replace(
                    f"<message-Inbox-{index}@example.test>".encode("ascii"),
                    invalid_value.encode("ascii"),
                    1,
                )
                source_path = self.source / f"invalid-{index}.eml"
                source_path.write_bytes(raw)

                strict_profile = self.write_profile()
                with self.assertRaisesRegex(
                    migration.MigrationError, "unsafe Message-ID"
                ):
                    migration.command_prepare(strict_profile, replace=False)
                self.assertFalse(strict_profile.manifest_path.exists())

                profile = self.write_profile(
                    missing_message_id_policy="deterministic_sha256_upload_copy"
                )
                with redirect_stdout(io.StringIO()):
                    migration.command_prepare(profile, replace=False)
                manifest = migration.load_manifest(profile)
                row = next(
                    item
                    for item in manifest["messages"]
                    if item["relative_path"] == source_path.name
                )
                expected_id = migration.deterministic_generated_message_id(
                    migration.sha256_bytes(raw)
                )
                provenance = row["message_id_provenance"]
                self.assertEqual(row["message_id"], expected_id)
                self.assertEqual(
                    provenance["kind"], "deterministic_sha256_upload_copy"
                )
                self.assertEqual(
                    provenance["source_header_state"], "invalid_single_header"
                )
                self.assertEqual(provenance["source_header_count"], 1)
                self.assertEqual(provenance["source_header_value"], invalid_value)
                self.assertEqual(source_path.read_bytes(), raw)
                checkpoint = migration.new_checkpoint(profile, manifest)
                prepared, _ = migration.source_bytes_for_state(
                    profile, row, checkpoint["states"][row["item_key"]]
                )
                prepared_headers = prepared.split(b"\r\n\r\n", 1)[0]
                self.assertIn(
                    ("Message-ID: " + expected_id).encode("ascii"),
                    prepared_headers,
                )
                self.assertNotIn(invalid_value.encode("ascii"), prepared_headers)

                source_path.unlink()
                profile.manifest_path.unlink()

    def test_multiple_message_id_headers_still_hard_stop(self):
        raw = eml_bytes(9).replace(
            b"Date:", b"Message-ID: <second@example.test>\r\nDate:", 1
        )
        (self.source / "multiple.eml").write_bytes(raw)
        profile = self.write_profile(
            missing_message_id_policy="deterministic_sha256_upload_copy"
        )
        with self.assertRaisesRegex(
            migration.MigrationError, "multiple Message-ID headers"
        ):
            migration.command_prepare(profile, replace=False)
        self.assertFalse(profile.manifest_path.exists())

    def test_audited_empty_placeholder_repair_is_narrow(self):
        raw = empty_boundaryless_placeholder_eml()
        prepared, repairs, occurrences, source_defects = (
            migration.prepare_source_bytes(raw)
        )
        self.assertEqual(
            repairs, [migration.REPAIR_CAFE24_EMPTY_RELATED]
        )
        self.assertEqual(occurrences[migration.REPAIR_CAFE24_EMPTY_RELATED], 1)
        self.assertEqual(source_defects, ["NoBoundaryInMultipartDefect"])
        self.assertIn(b"Content-Type: application/octet-stream", prepared)
        self.assertIn(b"Content-Transfer-Encoding: 7bits\r\n", prepared)
        self.assertEqual(
            migration.collect_defects(
                migration.BytesParser(policy=migration.policy.default).parsebytes(
                    prepared
                )
            ),
            [],
        )
        with self.assertRaisesRegex(
            migration.MigrationError, "do not match an audited Cafe24 repair"
        ):
            migration.prepare_source_bytes(
                empty_boundaryless_placeholder_eml(nonempty=True)
            )

    def test_audited_returned_text_separator_repair_is_narrow(self):
        raw = returned_text_missing_separator_eml()
        prepared, repairs, occurrences, source_defects = (
            migration.prepare_source_bytes(raw)
        )
        self.assertEqual(
            repairs, [migration.REPAIR_CAFE24_RETURNED_SEPARATOR]
        )
        self.assertEqual(
            occurrences[migration.REPAIR_CAFE24_RETURNED_SEPARATOR], 1
        )
        self.assertEqual(source_defects, ["MissingHeaderBodySeparatorDefect"])
        self.assertIn(
            b"Content-Transfer-Encoding: 7bit\r\n\r\n--\r\n",
            prepared,
        )
        self.assertEqual(
            migration.collect_defects(
                migration.BytesParser(policy=migration.policy.default).parsebytes(
                    prepared
                )
            ),
            [],
        )

    def test_manifest_rejects_generated_message_id_provenance_tampering(self):
        raw = headerless_eml_bytes(10)
        (self.source / "notice.eml").write_bytes(raw)
        profile = self.write_profile(
            missing_message_id_policy="deterministic_sha256_upload_copy"
        )
        with redirect_stdout(io.StringIO()):
            migration.command_prepare(profile, replace=False)
        manifest = json.loads(profile.manifest_path.read_text(encoding="utf-8"))
        manifest["messages"][0]["message_id_provenance"][
            "generated_value"
        ] = "<tampered@migration.invalid>"
        manifest["inventory_sha256"] = migration.sha256_bytes(
            migration.canonical_json_bytes(manifest["messages"])
        )
        profile.manifest_path.write_text(
            json.dumps(manifest), encoding="utf-8"
        )
        with self.assertRaisesRegex(
            migration.MigrationError, "Generated Message-ID provenance"
        ):
            migration.load_manifest(profile)

    def test_exact_duplicate_files_use_one_upload_and_union_folder_labels(self):
        raw = eml_bytes(42, "shared")
        (self.source / "0.eml").write_bytes(raw)
        sent = self.source / "Sent"
        sent.mkdir()
        (sent / "1.eml").write_bytes(raw)
        profile = self.write_profile()
        with redirect_stdout(io.StringIO()):
            migration.command_prepare(profile, replace=False)
        manifest = migration.load_manifest(profile)

        self.assertEqual(manifest["source_eml_count"], 2)
        self.assertEqual(manifest["unique_gmail_upload_rows"], 1)
        self.assertEqual(manifest["exact_prepared_duplicate_source_rows"], 1)
        canonical = next(
            row for row in manifest["messages"] if row["action"] == "import"
        )
        duplicate = next(
            row
            for row in manifest["messages"]
            if row["action"] == "merge_exact_duplicate"
        )
        self.assertEqual(
            duplicate["represented_by_item_key"], canonical["item_key"]
        )
        self.assertEqual(
            set(canonical["target_label_names"]),
            {
                profile.label_prefix,
                f"{profile.label_prefix}/Inbox",
                f"{profile.label_prefix}/Sent",
            },
        )
        self.assertEqual(canonical["target_system_label_ids"], ["INBOX"])

        label_map = {
            name: f"Label_{index}"
            for index, name in enumerate(canonical["target_label_names"], start=1)
        }
        uploaded = []

        def fake_import_one(
            profile_arg,
            checkpoint,
            row,
            service,
            dependencies,
            labels,
        ):
            uploaded.append(row["item_key"])
            migration.save_state(
                profile_arg,
                checkpoint,
                row["item_key"],
                **self.verified_evidence(
                    row, labels, "gmail-canonical"
                ),
            )
            return "verified"

        with (
            mock.patch.object(
                migration,
                "load_authorized_credentials",
                return_value=(object(), object(), {}),
            ),
            mock.patch.object(
                migration, "ensure_gmail_labels", return_value=label_map
            ),
            mock.patch.object(
                migration,
                "final_reconcile_terminal_gmail",
                side_effect=self.fake_final_reconcile,
            ),
            mock.patch.object(migration, "import_one", side_effect=fake_import_one),
            redirect_stdout(io.StringIO()),
        ):
            result = migration.command_run(
                profile, profile.destination, manifest["source_eml_count"]
            )

        self.assertEqual(result, 0)
        self.assertEqual(uploaded, [canonical["item_key"]])
        checkpoint = migration.load_checkpoint(profile, manifest)
        duplicate_state = checkpoint["states"][duplicate["item_key"]]
        self.assertEqual(duplicate_state["status"], "duplicate_source_reviewed")
        self.assertEqual(
            duplicate_state["represented_by_gmail_id"], "gmail-canonical"
        )
        report = migration.build_report(profile, manifest, checkpoint)
        self.assertEqual(report["google_verified"], 1)
        self.assertEqual(report["duplicate_source_reviewed"], 1)
        self.assertEqual(report["gmail_covered_source_rows"], 2)
        self.assertTrue(report["accounted_complete"])
        self.assertTrue(report["gmail_complete"])

    def test_exact_duplicate_inherits_reviewed_local_only_canonical_outcome(self):
        raw = eml_bytes(43, "shared")
        (self.source / "0.eml").write_bytes(raw)
        sent = self.source / "Sent"
        sent.mkdir()
        (sent / "1.eml").write_bytes(raw)
        profile = self.write_profile()
        with redirect_stdout(io.StringIO()):
            migration.command_prepare(profile, replace=False)
        manifest = migration.load_manifest(profile)
        checkpoint = migration.new_checkpoint(profile, manifest)
        canonical = next(
            row for row in manifest["messages"] if row["action"] == "import"
        )
        duplicate = next(
            row
            for row in manifest["messages"]
            if row["action"] == "merge_exact_duplicate"
        )
        canonical_state = checkpoint["states"][canonical["item_key"]]
        canonical_state.update(
            status="local_only_reviewed",
            attempted_prepared_sha256=canonical["prepared_sha256"],
            google_error_fingerprint="400:invalidArgument:invalid attachment",
            decision_reason="Known Gmail security rejection; preserve exact source",
            source_preserved=True,
        )
        migration.save_checkpoint(profile, checkpoint)

        label_map = {
            name: f"Label_{index}"
            for index, name in enumerate(
                canonical["target_label_names"], start=1
            )
        }
        self.assertTrue(
            migration.resolve_exact_duplicate_source_row(
                profile, manifest, checkpoint, duplicate, label_map
            )
        )
        checked = migration.load_checkpoint(profile, manifest)
        duplicate_state = checked["states"][duplicate["item_key"]]
        self.assertEqual(
            duplicate_state["status"], "duplicate_local_only_reviewed"
        )
        report = migration.build_report(profile, manifest, checked)
        self.assertTrue(report["accounted_complete"])
        self.assertFalse(report["gmail_complete"])
        self.assertEqual(report["local_only_reviewed"], 2)

    def test_replacement_hash_mismatch_does_not_cover_exact_duplicate(self):
        raw = eml_bytes(44, "shared")
        (self.source / "0.eml").write_bytes(raw)
        sent = self.source / "Sent"
        sent.mkdir()
        (sent / "1.eml").write_bytes(raw)
        profile = self.write_profile()
        with redirect_stdout(io.StringIO()):
            migration.command_prepare(profile, replace=False)
        manifest = migration.load_manifest(profile)
        checkpoint = migration.new_checkpoint(profile, manifest)
        canonical = next(
            row for row in manifest["messages"] if row["action"] == "import"
        )
        duplicate = next(
            row
            for row in manifest["messages"]
            if row["action"] == "merge_exact_duplicate"
        )
        label_map = {
            name: f"Label_{index}"
            for index, name in enumerate(
                canonical["target_label_names"], start=1
            )
        }
        replacement_hash = "replacement-prepared-sha256"
        canonical_state = checkpoint["states"][canonical["item_key"]]
        canonical_state.update(
            **self.verified_evidence(
                canonical, label_map, "gmail-replacement"
            )
        )
        canonical_state["verified_prepared_sha256"] = replacement_hash
        canonical_state["replacement"] = {
            "prepared_sha256": replacement_hash,
            "source_original_preserved": True,
        }
        migration.save_checkpoint(profile, checkpoint)

        self.assertFalse(
            migration.resolve_exact_duplicate_source_row(
                profile, manifest, checkpoint, duplicate, label_map
            )
        )
        checked = migration.load_checkpoint(profile, manifest)
        duplicate_state = checked["states"][duplicate["item_key"]]
        self.assertEqual(
            duplicate_state["status"], "duplicate_pending_canonical"
        )
        report = migration.build_report(profile, manifest, checked)
        self.assertFalse(report["accounted_complete"])
        self.assertEqual(report["duplicate_source_reviewed"], 0)

    def test_retry_final_missing_resets_canonical_and_exact_duplicate(self):
        failure = {
            "checked_at": migration.utc_now(),
            "issues": ["final Gmail readback request failed"],
            "error_type": "FakeHttpError",
            "http_status": 404,
            "google_error_reasons": ["notFound"],
        }
        profile, manifest, canonical, duplicate = (
            self.exact_duplicate_checkpoint_with_final_failure(failure)
        )

        with redirect_stdout(io.StringIO()):
            migration.command_review(
                profile,
                canonical["item_key"],
                None,
                "retry-final-missing",
                "Exact-ID readback was 404 and a fresh Gmail search returned zero",
                None,
                None,
                False,
                False,
                True,
                True,
                False,
            )

        reloaded = migration.load_checkpoint(profile, manifest)
        canonical_state = reloaded["states"][canonical["item_key"]]
        duplicate_state = reloaded["states"][duplicate["item_key"]]
        self.assertEqual(canonical_state["status"], "pending")
        self.assertNotIn("gmail_message_id", canonical_state)
        self.assertEqual(
            canonical_state["resolved_final_reconciliation_failure"], failure
        )
        self.assertEqual(
            canonical_state["review_history"][-1]["decision"],
            "retry-final-missing",
        )
        self.assertEqual(
            duplicate_state["status"], "duplicate_pending_canonical"
        )
        self.assertNotIn("represented_by_gmail_id", duplicate_state)
        self.assertNotIn("represented_prepared_sha256", duplicate_state)
        self.assertEqual(
            duplicate_state["review_history"][-1]["decision"],
            "retry-final-missing",
        )
        self.assertEqual(
            duplicate_state["prior_duplicate_representation"][-1][
                "represented_by_gmail_id"
            ],
            "gmail-canonical-final-failure",
        )

        report = migration.build_report(profile, manifest, reloaded)
        self.assertEqual(report["source_eml_denominator"], 2)
        self.assertEqual(report["accounted_for"], 0)
        self.assertEqual(report["blocking"], 0)
        self.assertEqual(report["pending_or_inflight"], 2)
        self.assertFalse(report["accounted_complete"])
        self.assertFalse(report["gmail_complete"])
        self.assertEqual(report["gmail_covered_source_rows"], 0)
        exceptions = {
            item["item_key"]: item for item in report["exceptions"]
        }
        self.assertEqual(
            exceptions[canonical["item_key"]]["decision"],
            "retry_confirmed_missing_terminal_gmail_row",
        )
        self.assertEqual(
            exceptions[duplicate["item_key"]]["decision"],
            "canonical_missing_reset_duplicate_to_pending",
        )
        canonical_exception = exceptions[canonical["item_key"]]
        self.assertEqual(
            canonical_exception["resolved_final_reconciliation_failure"],
            failure,
        )
        self.assertEqual(
            canonical_exception["prior_terminal_gmail_evidence"][-1][
                "gmail_message_id"
            ],
            "gmail-canonical-final-failure",
        )
        self.assertEqual(
            canonical_exception["prior_terminal_gmail_evidence"][-1][
                "final_reconciliation_failure"
            ],
            failure,
        )
        duplicate_exception = exceptions[duplicate["item_key"]]
        self.assertEqual(
            duplicate_exception["prior_duplicate_representation"][-1][
                "represented_by_gmail_id"
            ],
            "gmail-canonical-final-failure",
        )
        self.assertEqual(
            duplicate_exception["prior_duplicate_representation"][-1][
                "final_reconciliation_failure"
            ]["issues"],
            ["canonical final readback failed"],
        )

    def test_local_only_final_failure_closes_canonical_and_exact_duplicate(self):
        failure = {
            "checked_at": migration.utc_now(),
            "issues": ["final readback subject differs from the source"],
        }
        profile, manifest, canonical, duplicate = (
            self.exact_duplicate_checkpoint_with_final_failure(failure)
        )

        with redirect_stdout(io.StringIO()):
            migration.command_review(
                profile,
                canonical["item_key"],
                None,
                "local-only-final-failure",
                "Final Gmail evidence cannot be trusted; retain both exact sources locally",
                None,
                None,
                False,
                True,
                False,
                True,
                False,
            )

        reloaded = migration.load_checkpoint(profile, manifest)
        canonical_state = reloaded["states"][canonical["item_key"]]
        duplicate_state = reloaded["states"][duplicate["item_key"]]
        self.assertEqual(canonical_state["status"], "local_only_reviewed")
        self.assertNotIn("gmail_message_id", canonical_state)
        self.assertTrue(canonical_state["source_preserved"])
        self.assertEqual(
            canonical_state["resolved_final_reconciliation_failure"], failure
        )
        self.assertEqual(
            duplicate_state["status"], "duplicate_local_only_reviewed"
        )
        self.assertNotIn("represented_by_gmail_id", duplicate_state)
        self.assertTrue(duplicate_state["source_preserved"])
        self.assertEqual(
            duplicate_state["review_history"][-1]["decision"],
            "local-only-final-failure",
        )

        report = migration.build_report(profile, manifest, reloaded)
        self.assertEqual(report["source_eml_denominator"], 2)
        self.assertEqual(report["accounted_for"], 2)
        self.assertEqual(report["blocking"], 0)
        self.assertEqual(report["pending_or_inflight"], 0)
        self.assertTrue(report["accounted_complete"])
        self.assertFalse(report["gmail_complete"])
        self.assertEqual(report["gmail_covered_source_rows"], 0)
        self.assertEqual(report["local_only_reviewed"], 2)
        self.assertEqual(report["final_reconciliation_failure_rows"], [])
        exceptions = {
            item["item_key"]: item for item in report["exceptions"]
        }
        self.assertEqual(
            exceptions[canonical["item_key"]]["decision"],
            "terminal_gmail_failure_closed_local_only",
        )
        self.assertEqual(
            exceptions[duplicate["item_key"]]["decision"],
            "canonical_final_failure_closed_exact_copy_local_only",
        )
        canonical_exception = exceptions[canonical["item_key"]]
        self.assertEqual(
            canonical_exception["resolved_final_reconciliation_failure"],
            failure,
        )
        self.assertEqual(
            canonical_exception["previous_terminal_gmail_id"],
            "gmail-canonical-final-failure",
        )
        duplicate_exception = exceptions[duplicate["item_key"]]
        self.assertEqual(
            duplicate_exception["resolved_final_reconciliation_failure"][
                "issues"
            ],
            ["canonical final readback failed"],
        )
        self.assertEqual(
            duplicate_exception["prior_duplicate_representation"][-1][
                "represented_by_gmail_id"
            ],
            "gmail-canonical-final-failure",
        )

    def test_run_crosses_250_in_one_authorized_process_and_rerun_writes_zero(self):
        profile, manifest = self.prepare(count=251, nested=True)
        label_map = {
            name: f"Label_{index}"
            for index, name in enumerate(
                sorted(
                    {
                        name
                        for row in manifest["messages"]
                        for name in row["target_label_names"]
                    }
                ),
                start=1,
            )
        }
        imported = []

        def fake_import_one(
            profile_arg,
            checkpoint,
            row,
            service,
            dependencies,
            labels,
        ):
            imported.append(row["item_key"])
            migration.save_state(
                profile_arg,
                checkpoint,
                row["item_key"],
                **self.verified_evidence(
                    row, labels, f"gmail-{len(imported)}"
                ),
            )
            return "verified"

        with (
            mock.patch.object(
                migration,
                "load_authorized_credentials",
                return_value=(object(), object(), {}),
            ) as auth,
            mock.patch.object(
                migration, "ensure_gmail_labels", return_value=label_map
            ),
            mock.patch.object(
                migration,
                "final_reconcile_terminal_gmail",
                side_effect=self.fake_final_reconcile,
            ),
            mock.patch.object(migration, "import_one", side_effect=fake_import_one),
            redirect_stdout(io.StringIO()),
        ):
            result = migration.command_run(
                profile, profile.destination, manifest["source_eml_count"]
            )
        self.assertEqual(result, 0)
        self.assertEqual(len(imported), 251)
        self.assertEqual(auth.call_count, 1)
        checkpoint = migration.load_checkpoint(profile, manifest)
        self.assertTrue(migration.build_report(profile, manifest, checkpoint)["complete"])

        with (
            mock.patch.object(
                migration,
                "load_authorized_credentials",
                return_value=(object(), object(), {}),
            ),
            mock.patch.object(
                migration, "ensure_gmail_labels", return_value=label_map
            ),
            mock.patch.object(
                migration,
                "final_reconcile_terminal_gmail",
                side_effect=self.fake_final_reconcile,
            ),
            mock.patch.object(migration, "import_one") as no_more_imports,
            redirect_stdout(io.StringIO()),
        ):
            rerun = migration.command_run(
                profile, profile.destination, manifest["source_eml_count"]
            )
        self.assertEqual(rerun, 0)
        no_more_imports.assert_not_called()

    def test_google_stop_review_and_resume_without_new_checkpoint(self):
        profile, manifest = self.prepare(count=3)
        label_map = {
            name: f"Label_{index}"
            for index, name in enumerate(
                sorted(
                    {
                        name
                        for row in manifest["messages"]
                        for name in row["target_label_names"]
                    }
                ),
                start=1,
            )
        }
        blocked_key = manifest["messages"][1]["item_key"]

        def first_run_import(
            profile_arg,
            checkpoint,
            row,
            service,
            dependencies,
            labels,
        ):
            if row["item_key"] == blocked_key:
                migration.save_state(
                    profile_arg,
                    checkpoint,
                    row["item_key"],
                    status="google_rejected",
                    http_status=400,
                    google_error="Invalid attachment",
                    google_error_fingerprint=(
                        "400:invalidArgument:invalid attachment"
                    ),
                    gmail_message_id="",
                    source_preserved=True,
                )
                return "blocked"
            migration.save_state(
                profile_arg,
                checkpoint,
                row["item_key"],
                **self.verified_evidence(
                    row, labels, "gmail-first"
                ),
            )
            return "verified"

        with (
            mock.patch.object(
                migration,
                "load_authorized_credentials",
                return_value=(object(), object(), {}),
            ),
            mock.patch.object(
                migration, "ensure_gmail_labels", return_value=label_map
            ),
            mock.patch.object(migration, "import_one", side_effect=first_run_import),
            redirect_stdout(io.StringIO()),
            redirect_stderr(io.StringIO()),
        ):
            with self.assertRaises(migration.RunBlocked):
                migration.command_run(
                    profile, profile.destination, manifest["source_eml_count"]
                )

        with redirect_stdout(io.StringIO()):
            migration.command_review(
                profile,
                blocked_key,
                None,
                "local-only",
                "Reviewed Gmail rejection; preserve original locally",
                None,
                None,
                True,
                False,
                False,
                False,
                False,
            )

        resumed_imports = []

        def resumed_import(
            profile_arg,
            checkpoint,
            row,
            service,
            dependencies,
            labels,
        ):
            resumed_imports.append(row["item_key"])
            migration.save_state(
                profile_arg,
                checkpoint,
                row["item_key"],
                **self.verified_evidence(
                    row, labels, "gmail-last"
                ),
            )
            return "verified"

        with (
            mock.patch.object(
                migration,
                "load_authorized_credentials",
                return_value=(object(), object(), {}),
            ),
            mock.patch.object(
                migration, "ensure_gmail_labels", return_value=label_map
            ),
            mock.patch.object(
                migration,
                "final_reconcile_terminal_gmail",
                side_effect=self.fake_final_reconcile,
            ),
            mock.patch.object(migration, "import_one", side_effect=resumed_import),
            redirect_stdout(io.StringIO()),
        ):
            result = migration.command_run(
                profile, profile.destination, manifest["source_eml_count"]
            )
        self.assertEqual(result, 0)
        self.assertEqual(resumed_imports, [manifest["messages"][2]["item_key"]])
        checkpoint = migration.load_checkpoint(profile, manifest)
        report = migration.build_report(profile, manifest, checkpoint)
        self.assertTrue(report["complete"])
        self.assertEqual(report["google_verified"], 2)
        self.assertEqual(report["local_only_reviewed"], 1)

    def test_source_drift_stops_before_google(self):
        profile, manifest = self.prepare(count=2)
        (self.source / "0.eml").write_bytes(eml_bytes(999))
        with self.assertRaises(migration.MigrationError):
            migration.validate_source_snapshot(profile, manifest)

    def test_source_is_rescanned_after_uploads_before_completion(self):
        profile, manifest = self.prepare(count=1)
        row = manifest["messages"][0]

        def import_then_drift(
            profile_arg,
            checkpoint,
            row_arg,
            service,
            dependencies,
            labels,
        ):
            migration.save_state(
                profile_arg,
                checkpoint,
                row_arg["item_key"],
                **self.verified_evidence(
                    row_arg, labels, "gmail-1"
                ),
            )
            (self.source / row_arg["relative_path"]).write_bytes(eml_bytes(999))
            return "verified"

        with (
            mock.patch.object(
                migration,
                "load_authorized_credentials",
                return_value=(object(), object(), {}),
            ),
            mock.patch.object(
                migration,
                "ensure_gmail_labels",
                return_value={
                    name: f"Label_{index}"
                    for index, name in enumerate(
                        row["target_label_names"], start=1
                    )
                },
            ),
            mock.patch.object(
                migration, "final_reconcile_terminal_gmail", return_value=True
            ),
            mock.patch.object(migration, "import_one", side_effect=import_then_drift),
            redirect_stdout(io.StringIO()),
        ):
            with self.assertRaisesRegex(migration.MigrationError, "Source drift"):
                migration.command_run(
                    profile, profile.destination, manifest["source_eml_count"]
                )

    def test_exact_invalid_attachment_is_narrowly_classified(self):
        error = FakeHttpError(
            400,
            "invalidArgument",
            "Invalid attachment. Please check https://support.google.com/mail/answer/6590.",
        )
        self.assertEqual(
            migration.classify_import_error(error),
            "known_google_security_rejection",
        )
        unrelated = FakeHttpError(400, "invalidArgument", "Malformed request")
        self.assertEqual(
            migration.classify_import_error(unrelated), "google_rejected"
        )

    def test_confirmed_known_security_rejection_is_local_only_and_continues(self):
        profile, manifest = self.prepare(count=1)
        row = manifest["messages"][0]
        checkpoint = migration.new_checkpoint(profile, manifest)
        label_map = {
            name: f"Label_{index}"
            for index, name in enumerate(row["target_label_names"], start=1)
        }
        error = FakeHttpError(
            400,
            "invalidArgument",
            "Invalid attachment. Please check https://support.google.com/mail/answer/6590.",
        )

        class ImportRequest:
            def execute(self, num_retries=0):
                self_outer.assertEqual(num_retries, 0)
                raise error

        class Messages:
            def import_(self, **kwargs):
                return ImportRequest()

        class Users:
            def messages(self):
                return Messages()

        class Service:
            def users(self):
                return Users()

        self_outer = self
        with mock.patch.object(migration, "search_gmail_ids", return_value=[]):
            outcome = migration.import_one(
                profile,
                checkpoint,
                row,
                Service(),
                {"MediaIoBaseUpload": lambda *args, **kwargs: object()},
                label_map,
                continue_known_security_rejections=True,
            )
        self.assertEqual(outcome, "local_only")
        checked = migration.load_checkpoint(profile, manifest)
        state = checked["states"][row["item_key"]]
        self.assertEqual(state["status"], "local_only_reviewed")
        self.assertEqual(
            state["decision"], "run_confirmed_known_google_security_policy"
        )
        self.assertEqual(state["gmail_message_id"], "")
        self.assertTrue(state["source_preserved"])

    def test_rate_and_lost_response_are_uncertain(self):
        rate = FakeHttpError(403, "rateLimitExceeded", "Slow down")
        server = FakeHttpError(503, "backendError", "Unavailable")
        self.assertEqual(migration.classify_import_error(rate), "uncertain")
        self.assertEqual(migration.classify_import_error(server), "uncertain")
        self.assertEqual(
            migration.classify_import_error(TimeoutError("lost response")),
            "uncertain",
        )

    def test_gmail_import_size_boundary(self):
        migration.validate_gmail_import_size(1)
        migration.validate_gmail_import_size(migration.GMAIL_IMPORT_MAX_BYTES)
        for invalid in (
            0,
            -1,
            migration.GMAIL_IMPORT_MAX_BYTES + 1,
            True,
            "1",
        ):
            with self.subTest(invalid=invalid), self.assertRaises(
                migration.MigrationError
            ):
                migration.validate_gmail_import_size(invalid)

    def test_import_one_uses_single_request_multipart_with_durable_evidence(self):
        profile, manifest = self.prepare(count=1)
        row = manifest["messages"][0]
        checkpoint = migration.new_checkpoint(profile, manifest)
        label_map = {
            name: f"Label_{index}"
            for index, name in enumerate(row["target_label_names"], start=1)
        }
        expected_label_ids = migration.expected_label_ids_for_row(row, label_map)
        events = []
        media_calls = []
        import_calls = []

        def fake_media(stream, **kwargs):
            media_calls.append((stream.read(), kwargs))
            return object()

        class ImportRequest:
            def execute(self, num_retries=0):
                state = checkpoint["states"][row["item_key"]]
                events.append(("execute", num_retries, state["status"]))
                self_outer.assertEqual(
                    state["last_attempted_upload_protocol"],
                    migration.GMAIL_UPLOAD_PROTOCOL_SIMPLE,
                )
                self_outer.assertEqual(
                    state["last_attempted_upload_size_bytes"],
                    row["prepared_size_bytes"],
                )
                return {
                    "id": "gmail-simple-1",
                    "threadId": "thread-simple-1",
                    "labelIds": expected_label_ids,
                    "internalDate": str(row["expected_internal_date_ms"]),
                }

        class Messages:
            def import_(self, **kwargs):
                import_calls.append(kwargs)
                return ImportRequest()

        class Users:
            def messages(self):
                return Messages()

        class Service:
            def users(self):
                return Users()

        self_outer = self
        payload = {
            "id": "gmail-simple-1",
            "threadId": "thread-simple-1",
            "internalDate": str(row["expected_internal_date_ms"]),
            "labelIds": expected_label_ids,
            "payload": {
                "headers": [
                    {"name": "Message-ID", "value": row["message_id"]},
                    {"name": "Date", "value": row["date_header"]},
                    {"name": "From", "value": row["from"]},
                    {"name": "To", "value": row["to"]},
                    {"name": "Cc", "value": row["cc"]},
                    {"name": "Subject", "value": row["subject"]},
                ]
            },
        }
        with (
            mock.patch.object(migration, "search_gmail_ids", return_value=[]),
            mock.patch.object(
                migration, "readback_message", return_value=payload
            ),
        ):
            outcome = migration.import_one(
                profile,
                checkpoint,
                row,
                Service(),
                {"MediaIoBaseUpload": fake_media},
                label_map,
            )

        self.assertEqual(outcome, "verified")
        self.assertEqual(events, [("execute", 0, "inflight")])
        self.assertEqual(len(media_calls), 1)
        uploaded, media_kwargs = media_calls[0]
        self.assertEqual(migration.sha256_bytes(uploaded), row["prepared_sha256"])
        self.assertEqual(
            media_kwargs,
            {"mimetype": "message/rfc822", "resumable": False},
        )
        self.assertEqual(len(import_calls), 1)
        self.assertEqual(import_calls[0]["body"], {"labelIds": expected_label_ids})
        checked = migration.load_checkpoint(profile, manifest)
        state = checked["states"][row["item_key"]]
        self.assertEqual(state["status"], "verified")
        self.assertEqual(
            state["last_attempted_upload_protocol"],
            migration.GMAIL_UPLOAD_PROTOCOL_SIMPLE,
        )
        report = migration.build_report(profile, manifest, checked)
        self.assertEqual(
            report["source_rows_by_last_attempted_upload_protocol"],
            {migration.GMAIL_UPLOAD_PROTOCOL_SIMPLE: 1},
        )

    def test_non_ascii_prepared_bytes_select_resumable_protocol(self):
        self.assertEqual(
            migration.select_gmail_upload_protocol(b"ASCII message\r\n"),
            migration.GMAIL_UPLOAD_PROTOCOL_SIMPLE,
        )
        self.assertEqual(
            migration.select_gmail_upload_protocol("한글\r\n".encode("utf-8")),
            migration.GMAIL_UPLOAD_PROTOCOL_RESUMABLE,
        )

    def test_status_zero_invalid_grant_is_auth_but_transport_is_temporary(self):
        invalid_grant = RuntimeError(
            "invalid_grant: token has been expired or revoked"
        )
        transport = OSError("temporary DNS resolution failure")
        self.assertEqual(
            migration.classify_import_error(invalid_grant), "auth_required"
        )
        with self.assertRaises(migration.AuthRequired):
            migration.raise_if_google_access_block(
                invalid_grant, "testing a refresh-token rejection"
            )
        self.assertEqual(
            migration.classify_import_error(transport), "uncertain"
        )
        self.assertIsNone(
            migration.raise_if_google_access_block(
                transport, "testing a transient transport failure"
            )
        )

        outcomes = iter([transport, {"ok": True}])

        class StatusZeroRequest:
            def execute(self, num_retries=0):
                outcome = next(outcomes)
                if isinstance(outcome, Exception):
                    raise outcome
                return outcome

        with mock.patch.object(migration.time, "sleep") as sleep:
            self.assertEqual(
                migration.execute_idempotent(
                    lambda: StatusZeroRequest(), attempts=2
                ),
                {"ok": True},
            )
        sleep.assert_called_once()

    def test_auth_policy_and_daily_limit_errors_are_distinguished(self):
        unauthorized = FakeHttpError(401, "authError", "Invalid credentials")
        domain_policy = FakeHttpError(
            403,
            "domainPolicy",
            "The domain policy does not allow this application",
        )
        daily_limit = FakeHttpError(
            403,
            "dailyLimitExceeded",
            "Daily Limit Exceeded",
        )
        self.assertEqual(
            migration.classify_import_error(unauthorized), "auth_required"
        )
        self.assertEqual(
            migration.classify_import_error(domain_policy),
            "policy_or_quota_block",
        )
        self.assertEqual(
            migration.classify_import_error(daily_limit),
            "policy_or_quota_block",
        )

    def test_wrong_account_guard(self):
        with self.assertRaises(migration.AuthRequired):
            migration.verify_exact_account(
                FakeService("wrong@example.test"), "person@example.test"
            )
        self.assertEqual(
            migration.verify_exact_account(
                FakeService("person@example.test"), "person@example.test"
            ),
            "person@example.test",
        )

    def test_file_token_store_is_0600_and_never_printed(self):
        (self.source / "0.eml").write_bytes(eml_bytes(0))
        profile = self.write_profile()
        secret = "refresh-token-that-must-not-be-printed"
        migration.save_token_json(
            profile,
            json.dumps(
                {
                    "client_id": profile.oauth_client_id,
                    "client_secret": "test-only",
                    "refresh_token": secret,
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "scopes": list(migration.REQUIRED_SCOPES),
                }
            ),
        )
        assert profile.token_file is not None
        self.assertEqual(os.stat(profile.token_file).st_mode & 0o777, 0o600)
        loaded = migration.load_token_json(profile)
        self.assertIn(secret, loaded)
        output = io.StringIO()
        with redirect_stdout(output):
            print("token_present:", loaded is not None)
        self.assertNotIn(secret, output.getvalue())

    def test_profile_rejects_relative_token_file_path(self):
        self.write_profile()
        profile_data = json.loads(self.profile_path.read_text(encoding="utf-8"))
        profile_data["token_store"] = {
            "type": "file",
            "path": "relative-token.json",
        }
        self.profile_path.write_text(json.dumps(profile_data), encoding="utf-8")
        with self.assertRaisesRegex(migration.MigrationError, "absolute path"):
            migration.load_profile(self.profile_path)

    def test_profile_rejects_token_path_collisions(self):
        self.write_profile()
        base = json.loads(self.profile_path.read_text(encoding="utf-8"))
        collision_paths = {
            "profile": self.profile_path,
            "oauth-client": self.oauth,
            "state-directory": self.state,
            "manifest": self.state / "manifest.json",
            "checkpoint": self.state / "checkpoint.json",
            "checkpoint-lock": self.state / "checkpoint.json.lock",
            "final-report": self.state / "final-report.json",
        }
        for label, collision_path in collision_paths.items():
            with self.subTest(label=label):
                profile_data = dict(base)
                profile_data["token_store"] = {
                    "type": "file",
                    "path": str(collision_path),
                }
                self.profile_path.write_text(
                    json.dumps(profile_data), encoding="utf-8"
                )
                with self.assertRaisesRegex(
                    migration.MigrationError, "collides"
                ):
                    migration.load_profile(self.profile_path)

    def test_profile_rejects_symlink_parent_token_alias_collisions(self):
        self.write_profile()
        base = json.loads(self.profile_path.read_text(encoding="utf-8"))
        alias_root = self.root / "alias-root"
        alias_root.symlink_to(self.root, target_is_directory=True)
        alias_paths = {
            "profile": alias_root / self.profile_path.name,
            "oauth-client": alias_root / self.oauth.name,
            "checkpoint": alias_root / self.state.name / "checkpoint.json",
        }
        for label, alias_path in alias_paths.items():
            with self.subTest(label=label):
                profile_data = dict(base)
                profile_data["token_store"] = {
                    "type": "file",
                    "path": str(alias_path),
                }
                self.profile_path.write_text(
                    json.dumps(profile_data), encoding="utf-8"
                )
                with self.assertRaisesRegex(
                    migration.MigrationError, "collides"
                ):
                    migration.load_profile(self.profile_path)

    def test_profile_rejects_case_variant_state_token_collision(self):
        self.write_profile()
        profile_data = json.loads(
            self.profile_path.read_text(encoding="utf-8")
        )
        profile_data["token_store"] = {
            "type": "file",
            "path": str(self.state / "CHECKPOINT.JSON"),
        }
        self.profile_path.write_text(
            json.dumps(profile_data), encoding="utf-8"
        )
        with self.assertRaisesRegex(migration.MigrationError, "collides"):
            migration.load_profile(self.profile_path)

    def test_stored_grant_with_narrow_scopes_requires_authorization(self):
        profile = self.write_profile()
        migration.save_token_json(
            profile,
            json.dumps(
                {
                    "client_id": profile.oauth_client_id,
                    "client_secret": "test-only",
                    "refresh_token": "narrow-refresh-token",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "scopes": [migration.REQUIRED_SCOPES[0]],
                }
            ),
        )
        with (
            mock.patch.object(
                migration,
                "google_dependencies",
                side_effect=AssertionError("scope rejection must happen before Google setup"),
            ),
            self.assertRaisesRegex(migration.AuthRequired, "lacks.*required scopes"),
        ):
            migration.load_authorized_credentials(profile)

    def test_authorize_requests_offline_consent_and_stores_after_account_check(self):
        profile = self.write_profile()
        token_json = json.dumps(
            {
                "client_id": profile.oauth_client_id,
                "refresh_token": "offline-refresh-token",
                "scopes": list(migration.REQUIRED_SCOPES),
            }
        )
        credentials = mock.Mock()
        credentials.refresh_token = "offline-refresh-token"
        credentials.to_json.return_value = token_json
        flow = mock.Mock()
        flow.credentials = credentials
        flow.oauth2session.token = {
            "scope": " ".join(migration.REQUIRED_SCOPES)
        }
        installed_app_flow = mock.Mock()
        installed_app_flow.from_client_secrets_file.return_value = flow

        with (
            mock.patch.object(
                migration,
                "google_dependencies",
                return_value={"InstalledAppFlow": installed_app_flow},
            ),
            mock.patch.object(
                migration,
                "build_gmail_service",
                return_value=FakeService(profile.destination),
            ),
            mock.patch.object(migration, "save_token_json") as save_token,
            redirect_stdout(io.StringIO()),
        ):
            result = migration.command_authorize(profile, reauthorize=False)

        self.assertEqual(result, 0)
        installed_app_flow.from_client_secrets_file.assert_called_once_with(
            str(profile.oauth_client), scopes=migration.REQUIRED_SCOPES
        )
        authorize_kwargs = flow.run_local_server.call_args.kwargs
        self.assertEqual(authorize_kwargs["access_type"], "offline")
        self.assertEqual(authorize_kwargs["prompt"], "consent select_account")
        self.assertEqual(authorize_kwargs["login_hint"], profile.destination)
        self.assertTrue(authorize_kwargs["open_browser"])
        save_token.assert_called_once_with(profile, token_json)

    def test_authorize_never_stores_a_wrong_account_grant(self):
        profile = self.write_profile()
        credentials = mock.Mock()
        credentials.refresh_token = "wrong-account-refresh-token"
        credentials.to_json.return_value = json.dumps(
            {
                "client_id": profile.oauth_client_id,
                "refresh_token": "wrong-account-refresh-token",
                "scopes": list(migration.REQUIRED_SCOPES),
            }
        )
        flow = mock.Mock()
        flow.credentials = credentials
        flow.oauth2session.token = {
            "scope": " ".join(migration.REQUIRED_SCOPES)
        }
        installed_app_flow = mock.Mock()
        installed_app_flow.from_client_secrets_file.return_value = flow

        with (
            mock.patch.object(
                migration,
                "google_dependencies",
                return_value={"InstalledAppFlow": installed_app_flow},
            ),
            mock.patch.object(
                migration,
                "build_gmail_service",
                return_value=FakeService("wrong@example.test"),
            ),
            mock.patch.object(migration, "save_token_json") as save_token,
            self.assertRaises(migration.AuthRequired),
        ):
            migration.command_authorize(profile, reauthorize=False)
        save_token.assert_not_called()

    def test_keychain_store_uses_stdin_not_process_arguments(self):
        (self.source / "0.eml").write_bytes(eml_bytes(0))
        # The subprocess is mocked below; permit profile validation on Linux too.
        security_stub = self.source / "security"
        security_stub.write_text("test stub", encoding="utf-8")
        with mock.patch.object(migration, "KEYCHAIN_SECURITY", security_stub):
            profile = self.write_profile(token_type="keychain")
        secret = "refresh-token-not-in-argv"
        token_json = json.dumps(
            {
                "client_id": profile.oauth_client_id,
                "client_secret": "test-only",
                "refresh_token": secret,
                "token_uri": "https://oauth2.googleapis.com/token",
                "scopes": list(migration.REQUIRED_SCOPES),
            }
        )
        completed_write = mock.Mock(returncode=0, stdout="", stderr="")
        completed_read = mock.Mock(returncode=0, stdout="", stderr="")

        def fake_run(argv, **kwargs):
            if argv[1:] == ["-q", "-i"]:
                return completed_write
            self.assertEqual(argv[1], "find-generic-password")
            command = run.call_args_list[0].kwargs["input"].strip().split()
            stored_hex = command[command.index("-X") + 1]
            completed_read.stdout = bytes.fromhex(stored_hex).decode("utf-8") + "\n"
            return completed_read

        with mock.patch.object(migration.subprocess, "run", side_effect=fake_run) as run:
            migration.save_token_json(profile, token_json)
        self.assertEqual(run.call_count, 2)
        positional, keywords = run.call_args_list[0]
        argv = positional[0]
        self.assertNotIn(secret, " ".join(argv))
        self.assertEqual(argv[1:], ["-q", "-i"])
        self.assertNotIn(secret, keywords["input"])
        command = keywords["input"].strip().split()
        self.assertEqual(command[0], "add-generic-password")
        stored_hex = command[command.index("-X") + 1]
        stored = json.loads(bytes.fromhex(stored_hex).decode("utf-8"))
        self.assertEqual(stored["refresh_token"], secret)
        self.assertEqual(
            stored["_migration_binding"],
            {
                "destination": profile.destination,
                "oauth_client_id": profile.oauth_client_id,
                "oauth_client_sha256": profile.oauth_client_sha256,
                "required_scopes": list(migration.REQUIRED_SCOPES),
            },
        )

    def test_readback_verifies_headers_date_and_labels(self):
        row = {
            "message_id": "<one@example.test>",
            "expected_internal_date_ms": 1789700400000,
            "from": "sender@example.test",
            "to": "person@example.test",
            "cc": "",
            "subject": "Example",
        }
        payload = {
            "id": "gmail-1",
            "internalDate": "1789700400000",
            "labelIds": ["INBOX", "Label_1"],
            "payload": {
                "headers": [
                    {"name": "Message-ID", "value": "<one@example.test>"},
                    {"name": "Date", "value": "Fri, 18 Sep 2026 12:00:00 +0900"},
                    {"name": "From", "value": "sender@example.test"},
                    {"name": "To", "value": "person@example.test"},
                    {"name": "Subject", "value": "Example"},
                ]
            },
        }
        self.assertEqual(
            migration.verify_readback_payload(
                row, "gmail-1", payload, ["INBOX", "Label_1"]
            ),
            [],
        )
        row["from"] = "예제조직 <organization@example.test>"
        payload["payload"]["headers"][2]["value"] = (
            '"예제조직" <organization@example.test>'
        )
        self.assertEqual(
            migration.verify_readback_payload(
                row, "gmail-1", payload, ["INBOX", "Label_1"]
            ),
            [],
        )
        row["from"] = "MAILER-DAEMON@relay.example.test"
        payload["payload"]["headers"][2]["value"] = (
            "Mail Delivery System <MAILER-DAEMON@relay.example.test>"
        )
        self.assertEqual(
            migration.verify_readback_payload(
                row, "gmail-1", payload, ["INBOX", "Label_1"]
            ),
            [],
        )
        row["to"] = "undisclosed-recipients:;"
        payload["payload"]["headers"][3]["value"] = "undisclosed-recipients:;"
        self.assertEqual(
            migration.verify_readback_payload(
                row, "gmail-1", payload, ["INBOX", "Label_1"]
            ),
            [],
        )
        row["cc"] = (
            "Example <organization@example.test>, Example <organization@example.test>, "
            "Other <other@example.test>"
        )
        payload["payload"]["headers"].append(
            {
                "name": "Cc",
                "value": (
                    "Example <organization@example.test>, Other <other@example.test>"
                ),
            }
        )
        self.assertEqual(
            migration.verify_readback_payload(
                row, "gmail-1", payload, ["INBOX", "Label_1"]
            ),
            [],
        )
        payload["labelIds"] = ["INBOX"]
        self.assertTrue(
            migration.verify_readback_payload(
                row, "gmail-1", payload, ["INBOX", "Label_1"]
            )
        )

    def test_review_local_only_preserves_denominator(self):
        profile, manifest = self.prepare(count=1)
        checkpoint = migration.new_checkpoint(profile, manifest)
        row = manifest["messages"][0]
        state = checkpoint["states"][row["item_key"]]
        state.update(
            status="google_rejected",
            http_status=400,
            google_error="Invalid attachment",
            google_error_fingerprint=(
                "400:invalidArgument:invalid attachment"
            ),
            gmail_message_id="",
            source_preserved=True,
        )
        migration.save_checkpoint(profile, checkpoint)
        with redirect_stdout(io.StringIO()):
            migration.command_review(
                profile,
                row["item_key"],
                None,
                "local-only",
                "Reviewed rejection; keep original locally",
                None,
                None,
                True,
                False,
                False,
                False,
                False,
            )
        reviewed = migration.load_checkpoint(profile, manifest)
        self.assertEqual(
            reviewed["states"][row["item_key"]]["status"],
            "local_only_reviewed",
        )
        report = migration.build_report(profile, manifest, reviewed)
        self.assertTrue(report["complete"])
        self.assertTrue(report["accounted_complete"])
        self.assertFalse(report["gmail_complete"])
        self.assertEqual(report["source_eml_denominator"], 1)
        self.assertEqual(report["local_only_reviewed"], 1)

    def test_known_statuses_partition_the_completion_denominator(self):
        profile = self.write_profile()
        statuses = sorted(migration.KNOWN_STATUSES)
        manifest = {
            "messages": [
                {"item_key": f"item-{index}"}
                for index, _ in enumerate(statuses)
            ]
        }
        checkpoint = {
            "states": {
                f"item-{index}": {
                    "status": status,
                    "relative_path": f"{index}.eml",
                }
                for index, status in enumerate(statuses)
            }
        }
        report = migration.build_report(profile, manifest, checkpoint)
        pending_statuses = (
            migration.KNOWN_STATUSES
            - migration.TERMINAL_STATUSES
            - migration.BLOCKING_STATUSES
        )
        self.assertTrue(
            migration.TERMINAL_STATUSES.isdisjoint(
                migration.BLOCKING_STATUSES
            )
        )
        self.assertEqual(
            report["accounted_for"]
            + report["blocking"]
            + report["pending_or_inflight"],
            len(statuses),
        )
        self.assertEqual(report["pending_or_inflight"], len(pending_statuses))
        self.assertFalse(report["accounted_complete"])
        self.assertFalse(report["gmail_complete"])

    def test_malformed_verified_checkpoint_state_is_rejected(self):
        profile, manifest = self.prepare(count=1)
        checkpoint = migration.new_checkpoint(profile, manifest)
        row = manifest["messages"][0]
        checkpoint["states"][row["item_key"]].update(
            status="verified",
            verified_at=migration.utc_now(),
            readback_issues=[],
        )
        migration.save_checkpoint(profile, checkpoint)
        with self.assertRaisesRegex(
            migration.MigrationError, "Verified evidence is incomplete"
        ):
            migration.load_checkpoint(profile, manifest)

    def test_ignored_preexisting_ids_are_not_reconciliation_candidates(self):
        profile, manifest = self.prepare(count=1)
        checkpoint = migration.new_checkpoint(profile, manifest)
        row = manifest["messages"][0]
        state = checkpoint["states"][row["item_key"]]
        state.update(
            status="uncertain",
            ignored_preexisting_gmail_ids=["gmail-preexisting"],
        )
        with mock.patch.object(
            migration,
            "search_gmail_ids",
            return_value=["gmail-preexisting"],
        ):
            reconciled = migration.reconcile_uncertain(
                profile,
                checkpoint,
                row,
                object(),
                [],
                delays=(0,),
            )
        self.assertFalse(reconciled)
        self.assertEqual(state["status"], "uncertain")
        self.assertEqual(
            state["reconciliation_observations"][-1]["new_candidate_ids"],
            [],
        )

    def test_ignore_preexisting_risk_remains_in_final_report(self):
        profile, manifest = self.prepare(count=1)
        checkpoint = migration.new_checkpoint(profile, manifest)
        row = manifest["messages"][0]
        state = checkpoint["states"][row["item_key"]]
        state.update(
            status="preexisting_conflict",
            preexisting_gmail_ids=["gmail-preexisting"],
        )
        migration.save_checkpoint(profile, checkpoint)

        with redirect_stdout(io.StringIO()):
            migration.command_review(
                profile,
                row["item_key"],
                None,
                "ignore-preexisting",
                "Reviewed candidate is not the source copy; accept duplicate risk",
                None,
                None,
                False,
                False,
                False,
                True,
                True,
            )

        reviewed = migration.load_checkpoint(profile, manifest)
        reviewed_state = reviewed["states"][row["item_key"]]
        self.assertEqual(reviewed_state["status"], "pending")
        self.assertEqual(
            reviewed_state["ignored_preexisting_gmail_ids"],
            ["gmail-preexisting"],
        )
        self.assertEqual(
            reviewed_state["review_history"][-1]["decision"],
            "ignore-preexisting",
        )

        reviewed_state.update(
            **self.verified_evidence(
                row,
                {
                    name: f"Label_{index}"
                    for index, name in enumerate(
                        row["target_label_names"], start=1
                    )
                },
                "gmail-new",
            )
        )
        report = migration.build_report(profile, manifest, reviewed)
        exception = next(
            item
            for item in report["exceptions"]
            if item["item_key"] == row["item_key"]
        )
        self.assertEqual(
            exception["decision"], "ignore_preexisting_and_import"
        )
        self.assertEqual(
            exception["ignored_preexisting_gmail_ids"],
            ["gmail-preexisting"],
        )

    def test_retry_uncertain_risk_remains_in_final_report(self):
        profile, manifest = self.prepare(count=1)
        checkpoint = migration.new_checkpoint(profile, manifest)
        row = manifest["messages"][0]
        state = checkpoint["states"][row["item_key"]]
        state.update(
            status="uncertain",
            reconciliation_observations=[
                {
                    "checked_at": migration.utc_now(),
                    "match_ids": [],
                    "new_candidate_ids": [],
                }
            ],
        )
        migration.save_checkpoint(profile, checkpoint)

        with redirect_stdout(io.StringIO()):
            migration.command_review(
                profile,
                row["item_key"],
                None,
                "retry-uncertain",
                "Repeated search remained empty; accept explicit duplicate risk",
                None,
                None,
                False,
                False,
                True,
                True,
                False,
            )

        reviewed = migration.load_checkpoint(profile, manifest)
        reviewed_state = reviewed["states"][row["item_key"]]
        self.assertEqual(reviewed_state["status"], "pending")
        reviewed_state.update(
            **self.verified_evidence(
                row,
                {
                    name: f"Label_{index}"
                    for index, name in enumerate(
                        row["target_label_names"], start=1
                    )
                },
                "gmail-after-risky-retry",
            )
        )
        report = migration.build_report(profile, manifest, reviewed)
        exception = next(
            item
            for item in report["exceptions"]
            if item["item_key"] == row["item_key"]
        )
        self.assertEqual(
            exception["decision"], "retry_after_reviewed_uncertainty"
        )
        self.assertEqual(
            exception["review_history"][-1]["decision"],
            "retry-uncertain",
        )

    def test_checkpoint_lock_rejects_concurrent_process(self):
        profile, _ = self.prepare(count=1)
        with migration.exclusive_checkpoint_lock(profile.checkpoint_path):
            with self.assertRaises(migration.MigrationError):
                with migration.exclusive_checkpoint_lock(profile.checkpoint_path):
                    pass


if __name__ == "__main__":
    unittest.main()
