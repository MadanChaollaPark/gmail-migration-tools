# Sanitized historical reference: source-specific evidence and live configuration are not distributed.
'Offline Raw-header raw-header fallback contract tests using preserved source fixtures.\n\nNo credentials, checkpoint/profile writes, evidence writes, or network calls are\nused. The source files and the two earlier review records are read only.\n'

from __future__ import annotations

import base64
from contextlib import ExitStack, contextmanager
import copy
import hashlib
import json
from pathlib import Path
import re
from types import SimpleNamespace
import unittest
from unittest import mock

import raw_header_runner as adapter


HERE = Path(__file__).resolve().parent
SOURCE_ROOT = HERE / "source-union"
engine = adapter.engine
RECEIPT_ID = "offline-test-accepted-receipt"
LABELS = ["INBOX", "Label_offline_test"]
PRIMARY = ["Message-ID", "Date", "From", "To", "Cc", "Subject"]


def fingerprint(value):
    return hashlib.sha256(value).hexdigest()


def parse(value):
    return engine.BytesParser(policy=engine.policy.default).parsebytes(value)


def replace_header(raw, name, value):
    """Change one complete header without reserializing unrelated source bytes."""
    pattern = rb"(?im)^" + re.escape(name.encode("ascii")) + rb":[^\r\n]*(?:\r?\n[ \t][^\r\n]*)*"
    result, count = re.subn(pattern, lambda _: name.encode("ascii") + b": " + value.encode("utf-8"), raw, count=1)
    if count != 1:
        raise AssertionError(f"Fixture does not contain exactly one selected {name} header")
    return result


class RawHeaderFallbackTests(unittest.TestCase):
    def setUp(self):
        self.source_hashes = {}
        self.original_readback = engine.readback_message

    def tearDown(self):
        engine.readback_message = self.original_readback
        for path, expected in self.source_hashes.items():
            self.assertEqual(fingerprint(path.read_bytes()), expected)

    def fixture(self, kind="sender"):
        review = json.loads((HERE / f"{kind}-header-review.json").read_text())
        path = SOURCE_ROOT / (review["source_sha256"] + ".eml")
        source = path.read_bytes()
        self.source_hashes[path] = fingerprint(source)
        self.assertEqual(fingerprint(source), review["source_sha256"])
        prepared, row = engine.parse_source_path(path, SOURCE_ROOT)
        self.assertEqual(row["item_key"], review["item_key"])
        self.assertEqual(fingerprint(prepared), review["prepared_sha256"])
        row.update(target_label_names=["offline archive"], target_system_label_ids=["INBOX"])
        message = parse(prepared)
        metadata = {
            "id": RECEIPT_ID,
            "threadId": "offline-test-thread",
            "labelIds": list(LABELS),
            "internalDate": str(row["expected_internal_date_ms"]),
            "payload": {"headers": [
                {"name": name, "value": str(message.get(name, ""))}
                for name in PRIMARY
            ]},
        }
        selected_name = "From" if kind == "sender" else "To"
        selected_value = review["metadata_from"] if kind == "sender" else review["metadata_to_value"]
        self.set_metadata_header(metadata, selected_name, selected_value)
        self.assertEqual(
            engine.verify_readback_payload(row, RECEIPT_ID, metadata, LABELS),
            review["metadata_issues"],
        )
        raw = b"Received: by offline-test.invalid; source fixture only\r\n" + prepared
        profile = SimpleNamespace(
            state_dir=HERE / "offline-test-state-never-written",
            source_root=SOURCE_ROOT,
            destination='example-a88c3515@example.org',
            source_mailbox='example-a88c3515@example.org',
            migration_id="sg-offline-test",
        )
        state = {
            "status": "uploaded_unverified",
            "gmail_message_id": RECEIPT_ID,
            "source_sha256": row["source_sha256"],
            "prepared_sha256": row["prepared_sha256"],
            "uploaded_prepared_sha256": row["prepared_sha256"],
            "message_id": row["message_id"],
            "relative_path": row["relative_path"],
        }
        return SimpleNamespace(
            prepared=prepared, row=row, state=state, metadata=metadata,
            raw=raw, profile=profile, manifest={
                "messages": [row], "source_mailbox": 'example-a88c3515@example.org',
                "expected_destination": 'example-a88c3515@example.org',
            },
            checkpoint={"states": {row["item_key"]: state}, "gmail_labels": {"offline archive": LABELS[1]}},
        )

    @staticmethod
    def set_metadata_header(payload, name, value):
        for header in payload["payload"]["headers"]:
            if header["name"].casefold() == name.casefold():
                header["value"] = value
                return
        raise AssertionError(f"Missing fixture header {name}")

    @contextmanager
    def installed(self, fixture, *, raw_change=None, response_change=None, source_error=None, write_error=None):
        raw = raw_change(fixture.raw) if raw_change else fixture.raw
        raw_response = {
            "id": RECEIPT_ID,
            "threadId": "offline-test-thread",
            "labelIds": list(LABELS),
            "internalDate": str(fixture.row["expected_internal_date_ms"]),
            "raw": base64.urlsafe_b64encode(raw).decode("ascii").rstrip("="),
        }
        if response_change:
            response_change(raw_response)
        service = mock.Mock(name="offline_gmail_service")
        request = object()
        service.users.return_value.messages.return_value.get.return_value = request

        def execute(factory, *args, **kwargs):
            self.assertIs(factory(), request)
            return copy.deepcopy(raw_response)

        with ExitStack() as stack:
            metadata_reader = stack.enter_context(mock.patch.object(adapter, "_original_readback_message", return_value=fixture.metadata))
            checkpoint_reader = stack.enter_context(mock.patch.object(engine, "load_checkpoint", return_value=fixture.checkpoint))
            source_reader = stack.enter_context(mock.patch.object(
                engine, "source_bytes_for_state",
                return_value=(fixture.prepared, fixture.row), side_effect=source_error,
            ))
            raw_reader = stack.enter_context(mock.patch.object(engine, "execute_idempotent", side_effect=execute))
            writer = stack.enter_context(mock.patch.object(engine, "write_json_atomic", side_effect=write_error))
            adapter.install_run_readback(fixture.profile, fixture.manifest)
            yield SimpleNamespace(
                service=service, raw=raw, raw_reader=raw_reader, writer=writer,
                metadata_reader=metadata_reader, source_reader=source_reader,
                checkpoint_reader=checkpoint_reader,
            )

    def assert_denied(self, fixture, environment):
        """A refusal may preserve the metadata mismatch or explicitly stop."""
        try:
            result = engine.readback_message(environment.service, RECEIPT_ID)
        except (engine.MigrationError, OSError):
            return
        self.assertEqual(result, fixture.metadata)
        self.assertTrue(engine.verify_readback_payload(fixture.row, RECEIPT_ID, result, LABELS))

    def test_both_observed_normalizations_accept_only_preserved_raw_content(self):
        for kind in ("sender", "recipient"):
            with self.subTest(kind=kind):
                fixture = self.fixture(kind)
                with self.installed(fixture) as env:
                    result = engine.readback_message(env.service, RECEIPT_ID)
                    self.assertEqual(engine.verify_readback_payload(fixture.row, RECEIPT_ID, result, LABELS), [])
                    self.assertNotEqual(result, fixture.metadata)
                    env.metadata_reader.assert_called_once_with(env.service, RECEIPT_ID)
                    env.checkpoint_reader.assert_called_with(fixture.profile, fixture.manifest, create=False)
                    self.assertEqual(env.source_reader.call_args_list, [
                        mock.call(fixture.profile, fixture.row, fixture.state),
                        mock.call(fixture.profile, fixture.row, fixture.state),
                    ])
                    env.raw_reader.assert_called_once()
                    kwargs = env.service.users.return_value.messages.return_value.get.call_args.kwargs
                    self.assertEqual({key: kwargs[key] for key in ("userId", "id", "format")}, {
                        "userId": "me", "id": RECEIPT_ID, "format": "raw",
                    })
                    env.writer.assert_called_once()
                    evidence_path, evidence = env.writer.call_args.args[:2]
                    self.assertEqual(Path(evidence_path).parent, fixture.profile.state_dir / "raw-header-verifications")
                    self.assertEqual(Path(evidence_path).name, fixture.row["item_key"] + ".json")
                    for gate in ("passed", "primary_headers_equal", "mime_equal", "source_files_unchanged"):
                        self.assertIs(evidence[gate], True)
                    self.assertEqual(evidence["raw_readback_issues"], [])
                    self.assertEqual(evidence["source_mime"], evidence["gmail_mime"])
                    serialized = json.dumps(evidence, sort_keys=True)
                    for binding in (
                        fixture.row["item_key"], RECEIPT_ID, fixture.profile.destination,
                        fixture.row["source_sha256"], fixture.row["prepared_sha256"], fingerprint(env.raw),
                    ):
                        self.assertIn(binding, serialized)

    def test_clean_metadata_uses_no_raw_fallback(self):
        fixture = self.fixture()
        self.set_metadata_header(fixture.metadata, "From", fixture.row["from"])
        with self.installed(fixture) as env:
            self.assertEqual(engine.readback_message(env.service, RECEIPT_ID), fixture.metadata)
            env.raw_reader.assert_not_called()
            env.source_reader.assert_not_called()
            env.writer.assert_not_called()

    def test_ineligible_metadata_issues_do_not_trigger_raw_request(self):
        mutations = {
            "id": lambda p: p.update(id="different-receipt"),
            "message-id": lambda p: self.set_metadata_header(p, "Message-ID", "<wrong@example.invalid>"),
            "date": lambda p: self.set_metadata_header(p, "Date", "Mon, 1 Jan 2001 00:00:00 +0000"),
            "internal-date": lambda p: p.update(internalDate="1"),
            "labels": lambda p: p.update(labelIds=[]),
        }
        for name, mutation in mutations.items():
            with self.subTest(name=name):
                fixture = self.fixture()
                mutation(fixture.metadata)
                with self.installed(fixture) as env:
                    self.assert_denied(fixture, env)
                    env.raw_reader.assert_not_called()
                    env.writer.assert_not_called()

    def test_bad_raw_receipt_metadata_cannot_be_overridden(self):
        mutations = {
            "id": lambda p: p.update(id="different-receipt"),
            "internal-date": lambda p: p.update(internalDate="1"),
            "labels": lambda p: p.update(labelIds=[]),
            "missing-raw": lambda p: p.pop("raw"),
            "invalid-base64": lambda p: p.update(raw="%%%"),
        }
        for name, mutation in mutations.items():
            with self.subTest(name=name):
                fixture = self.fixture()
                with self.installed(fixture, response_change=mutation) as env:
                    self.assert_denied(fixture, env)

    def test_changed_decoded_body_is_rejected(self):
        fixture = self.fixture()
        with self.installed(fixture, raw_change=lambda raw: raw + b"\r\nOffline body tampering\r\n") as env:
            self.assert_denied(fixture, env)

    def test_changed_primary_header_is_rejected(self):
        mutations = {
            "from": lambda raw: replace_header(raw, "From", "changed@example.invalid"),
            "to": lambda raw: replace_header(raw, "To", "changed@example.invalid"),
            "subject": lambda raw: replace_header(raw, "Subject", "Changed subject"),
            "message-id": lambda raw: replace_header(raw, "Message-ID", "<changed@example.invalid>"),
            "date": lambda raw: replace_header(raw, "Date", "Mon, 1 Jan 2001 00:00:00 +0000"),
            "duplicate-to": lambda raw: b'To: example-a88c3515@example.org\r\n' + raw,
            "equivalent-date": lambda raw: replace_header(raw, "Date", "Wed, 5 Jan 2022 17:42:20 +0100"),
            "equivalent-from": lambda raw: replace_header(raw, "From", 'Different display name <example-4179d5fa@example.org>'),
        }
        for name, mutation in mutations.items():
            with self.subTest(name=name):
                fixture = self.fixture()
                with self.installed(fixture, raw_change=mutation) as env:
                    self.assert_denied(fixture, env)

    def test_changed_mime_type_is_rejected(self):
        fixture = self.fixture()
        with self.installed(fixture, raw_change=lambda raw: replace_header(raw, "Content-Type", "text/plain; charset=UTF-8")) as env:
            self.assert_denied(fixture, env)

    def test_changed_attachment_metadata_is_rejected(self):
        fixture = self.fixture("recipient")
        original = b'example-7a10dbd7@example.org'
        self.assertIn(original, fixture.raw)
        with self.installed(fixture, raw_change=lambda raw: raw.replace(original, b"altered-content-id@example.invalid", 1)) as env:
            self.assert_denied(fixture, env)

    def test_missing_or_ambiguous_receipt_ownership_is_rejected(self):
        for ambiguous in (False, True):
            with self.subTest(ambiguous=ambiguous):
                fixture = self.fixture()
                if ambiguous:
                    other_row = dict(fixture.row, item_key="second-owner")
                    fixture.manifest["messages"].append(other_row)
                    fixture.checkpoint["states"]["second-owner"] = copy.deepcopy(fixture.state)
                else:
                    fixture.state.pop("gmail_message_id")
                with self.installed(fixture) as env:
                    self.assert_denied(fixture, env)
                    env.raw_reader.assert_not_called()
                    env.writer.assert_not_called()

    def test_source_validation_failure_is_not_bypassed(self):
        fixture = self.fixture()
        with self.installed(fixture, source_error=engine.MigrationError("Source hash changed")) as env:
            self.assert_denied(fixture, env)
            env.writer.assert_not_called()

    def test_source_change_during_readback_cannot_be_accepted(self):
        fixture = self.fixture()
        changed = fixture.prepared + b"\r\nOffline source-change fixture\r\n"
        changed_row = dict(fixture.row, prepared_sha256=fingerprint(changed))
        with self.installed(fixture) as env:
            env.source_reader.side_effect = [
                (fixture.prepared, fixture.row), (changed, changed_row),
            ]
            self.assert_denied(fixture, env)
            env.writer.assert_not_called()

    def test_failed_evidence_write_cannot_accept_fallback(self):
        fixture = self.fixture()
        with self.installed(fixture, write_error=OSError("Offline simulated write failure")) as env:
            self.assert_denied(fixture, env)
            env.writer.assert_called_once()

    def test_install_rejects_every_non_sg_scope_identity(self):
        for location, field in (
            ("profile", "destination"),
            ("profile", "source_mailbox"),
            ("manifest", "source_mailbox"),
            ("manifest", "expected_destination"),
        ):
            with self.subTest(location=location, field=field):
                profile = SimpleNamespace(destination='example-a88c3515@example.org', source_mailbox='example-a88c3515@example.org')
                manifest = {
                    "source_mailbox": 'example-a88c3515@example.org',
                    "expected_destination": 'example-a88c3515@example.org', "messages": [],
                }
                if location == "profile":
                    setattr(profile, field, "another-mailbox@example.invalid")
                else:
                    manifest[field] = "another-mailbox@example.invalid"
                before = engine.readback_message
                with mock.patch.object(engine, "load_checkpoint") as checkpoint_reader, \
                     mock.patch.object(engine, "execute_idempotent") as raw_reader, \
                     mock.patch.object(engine, "write_json_atomic") as writer:
                    with self.assertRaisesRegex(engine.MigrationError, 'Raw-header mailbox'):
                        adapter.install_run_readback(profile, manifest)
                    self.assertIs(engine.readback_message, before)
                    checkpoint_reader.assert_not_called()
                    raw_reader.assert_not_called()
                    writer.assert_not_called()

    def test_non_run_main_resets_readback_without_loading_profile(self):
        for argv in (["status"], ["review"], ["preflight"], []):
            with self.subTest(argv=argv):
                engine.readback_message = mock.Mock(name="previously-installed-fallback")

                def invoke_main(received):
                    self.assertEqual(received, argv)
                    self.assertIs(engine.readback_message, adapter._original_readback_message)
                    return 23

                with mock.patch.dict(adapter.os.environ, {}, clear=True), \
                     mock.patch.object(engine, "main", side_effect=invoke_main) as main, \
                     mock.patch.object(engine, "parse_args") as parse_args, \
                     mock.patch.object(engine, "load_profile") as load_profile, \
                     mock.patch.object(engine, "load_manifest") as load_manifest, \
                     mock.patch.object(adapter, "install_run_readback") as install:
                    self.assertEqual(adapter.main(argv), 23)
                    main.assert_called_once_with(argv)
                    parse_args.assert_not_called()
                    load_profile.assert_not_called()
                    load_manifest.assert_not_called()
                    install.assert_not_called()


if __name__ == "__main__":
    raise SystemExit("Archived reference variant. Use the configurable v2 engine at the repository root.")
    unittest.main()
