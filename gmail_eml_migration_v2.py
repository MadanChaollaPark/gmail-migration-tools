#!/usr/bin/env python3
"""Source-preserving, resumable Cafe24 EML to Gmail migration engine.

The engine is deliberately split into explicit phases:

* ``prepare`` inventories every .eml below one source root and freezes a manifest.
* ``authorize`` performs the only interactive OAuth flow and persists an offline
  refresh credential in macOS Keychain (or a mode-0600 file fallback).
* ``run`` validates the complete source snapshot, verifies the exact Google
  account, and processes every pending manifest row sequentially.
* ``review`` records a human decision after a hard Google rejection without
  ever modifying the source EML.

The runner never opens a browser from ``run``.  A missing, revoked, or
scope-incompatible credential stops with AUTH_REQUIRED instead.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import io
import json
import os
import random
import re
import shlex
import stat
import subprocess
import sys
import tempfile
import time
from collections import Counter, defaultdict
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
from pathlib import Path
from typing import Any, Callable, Iterable


PROFILE_SCHEMA_VERSION = 1
MANIFEST_SCHEMA_VERSION = 4
CHECKPOINT_SCHEMA_VERSION = 2

REQUIRED_SCOPES = (
    "https://www.googleapis.com/auth/gmail.insert",
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.labels",
)

TERMINAL_STATUSES = {
    "verified",
    "verified_manual",
    "local_only_reviewed",
    "preexisting_reviewed",
    "duplicate_source_reviewed",
    "duplicate_local_only_reviewed",
}
BLOCKING_STATUSES = {
    "google_rejected",
    "uncertain",
    "review_required",
    "preexisting_conflict",
}
KNOWN_STATUSES = TERMINAL_STATUSES | BLOCKING_STATUSES | {
    "pending",
    "duplicate_pending_canonical",
    "inflight",
    "imported_pending_verification",
    "preexisting_pending_verification",
    "candidate_pending_verification",
}
TRANSIENT_HTTP_STATUSES = {408, 409, 425, 429, 500, 502, 503, 504}
TRANSIENT_REASONS = {
    "backendError",
    "rateLimitExceeded",
    "userRateLimitExceeded",
}
AUTH_ERROR_REASONS = {"authError", "insufficientPermissions"}
POLICY_OR_QUOTA_REASONS = {
    "accessNotConfigured",
    "dailyLimitExceeded",
    "domainPolicy",
    "forbidden",
    "quotaExceeded",
}
REAUTHORIZATION_MARKERS = (
    "invalid_grant",
    "invalid grant",
    "token has been expired or revoked",
    "unauthorized_client",
    "access_denied",
)
KNOWN_GMAIL_SECURITY_TEXT = (
    "invalid attachment",
    "please check https://support.google.com/mail/answer/6590",
)
DEFAULT_PROGRESS_EVERY = 250
DEFAULT_RECONCILIATION_DELAYS = (0.0, 5.0, 30.0)
GMAIL_IMPORT_MAX_BYTES = 150 * 1024 * 1024
GMAIL_UPLOAD_PROTOCOL_SIMPLE = "multipart_single_request_v1"
GMAIL_UPLOAD_PROTOCOL_RESUMABLE = "resumable_5mib_v1"
GMAIL_UPLOAD_PROTOCOLS = frozenset(
    {GMAIL_UPLOAD_PROTOCOL_SIMPLE, GMAIL_UPLOAD_PROTOCOL_RESUMABLE}
)
GMAIL_UPLOAD_STRATEGY = "ascii_multipart_else_resumable_v1"
KEYCHAIN_SECURITY = Path("/usr/bin/security")
CAFE24_RECEIVED_FOLD = re.compile(
    rb"^by\s+webmail-[^\s]+\.cafe24\.com\s+with\s+", re.IGNORECASE
)
CAFE24_RETURNED_TEXT_MISSING_SEPARATOR = re.compile(
    rb"(?m)^Content-Type: text/plain; charset=iso-8859-1\r\n"
    rb"Content-Transfer-Encoding: 7bit\r\n"
    rb"(?P<body>--\r\n\r\n--\r\n"
    rb"--=_webmail-[A-Za-z0-9._-]+--(?:\r\n|\Z))"
)
CAFE24_EMPTY_BOUNDARYLESS_RELATED = re.compile(
    rb"(?m)^--(?P<boundary>=_webmail-[A-Za-z0-9._-]+)\r\n"
    rb"(?P<content_type>Content-Type: multipart/related)\r\n"
    rb"Content-ID: <[0-9]+>\r\n"
    rb"\r\n"
    rb"Mime-Version: 1\.0\r\n"
    rb"\r\n"
    rb"Content-Transfer-Encoding: 7bits\r\n"
    rb"\r\n"
    rb"\r\n"
    rb"(?=--(?P=boundary)(?:--)?(?:\r\n|\Z))"
)
RFC_MESSAGE_ID = re.compile(r"^<[^<>\s@]+@[^<>\s@]+>$")
RFC_MESSAGE_ID_HEADER_BYTES = re.compile(
    rb"(?im)^Message-ID:[^\r\n]*(?:(?:\r\n|\n)[ \t][^\r\n]*)*"
)
REPAIR_CAFE24_RECEIVED_FOLD = "cafe24_received_fold_space_v1"
REPAIR_CAFE24_RETURNED_SEPARATOR = "cafe24_returned_text_part_separator_v1"
REPAIR_CAFE24_EMPTY_RELATED = "cafe24_empty_boundaryless_related_placeholder_v1"
REPAIR_GENERATED_MESSAGE_ID = "generated_message_id_sha256_upload_copy_v1"
MISSING_MESSAGE_ID_POLICIES = {
    "stop",
    "deterministic_sha256_upload_copy",
}


class MigrationError(RuntimeError):
    """A local validation or safety invariant failed."""


class AuthRequired(MigrationError):
    """The persisted OAuth grant is absent or no longer usable."""


class RunBlocked(MigrationError):
    """The migration stopped on a message that needs review or reconciliation."""


@dataclass(frozen=True)
class Profile:
    path: Path
    migration_id: str
    source_root: Path
    source_mailbox: str
    destination: str
    state_dir: Path
    oauth_client: Path
    oauth_client_id: str
    oauth_client_sha256: str
    label_prefix: str
    custom_label_policy: str
    root_folder: str
    inbox_folders: frozenset[str]
    progress_every: int
    token_store_type: str
    token_file: Path | None
    keychain_service: str
    keychain_account: str
    rejection_policy: str
    missing_message_id_policy: str
    message_id_collision_policy: str
    profile_fingerprint: str

    @property
    def manifest_path(self) -> Path:
        return self.state_dir / "manifest.json"

    @property
    def checkpoint_path(self) -> Path:
        return self.state_dir / "checkpoint.json"

    @property
    def report_path(self) -> Path:
        return self.state_dir / "final-report.json"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise MigrationError(f"Cannot read valid JSON from {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise MigrationError(f"Expected a JSON object in {path}.")
    return value


def write_json_atomic(path: Path, value: dict[str, Any], mode: int = 0o600) -> None:
    if not path.parent.exists():
        path.parent.mkdir(parents=True, mode=0o700)
    if not path.parent.is_dir():
        raise MigrationError(f"JSON parent is not a directory: {path.parent}")
    if path.parent.stat().st_uid != os.getuid():
        raise MigrationError(f"State directory is not owned by the current user: {path.parent}")
    parent_mode = stat.S_IMODE(path.parent.stat().st_mode)
    if parent_mode & 0o077:
        raise MigrationError(
            f"Sensitive JSON directory permissions are {oct(parent_mode)}; use a dedicated "
            f"owner-only directory (0o700): {path.parent}"
        )
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=path.name + ".", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = -1
            json.dump(value, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary.exists():
            temporary.unlink()


def normalize_mailbox(value: Any, field: str) -> str:
    mailbox = str(value or "").strip().lower()
    if (
        not mailbox
        or "@" not in mailbox
        or any(character.isspace() for character in mailbox)
        or "\r" in mailbox
        or "\n" in mailbox
    ):
        raise MigrationError(f"Profile {field} is not a valid mailbox address.")
    return mailbox


def normalize_scope_values(value: Any) -> set[str]:
    if isinstance(value, str):
        return {item for item in value.split() if item}
    if isinstance(value, (list, tuple, set, frozenset)):
        return {str(item) for item in value if str(item)}
    return set()


def normalize_folder_name(value: Any) -> str:
    folder = str(value or "").strip().replace("\\", "/").strip("/")
    if not folder or any(ord(character) < 32 for character in folder):
        raise MigrationError("Folder names must be nonempty and contain no controls.")
    return folder


def read_oauth_client_config(path: Path) -> tuple[str, str]:
    data = load_json(path)
    installed = data.get("installed")
    if not isinstance(installed, dict):
        raise MigrationError("OAuth JSON must describe a Desktop app ('installed').")
    client_id = str(installed.get("client_id", "")).strip()
    if not client_id:
        raise MigrationError("OAuth Desktop client JSON has no client_id.")
    auth_uri = str(installed.get("auth_uri", "")).strip()
    token_uri = str(installed.get("token_uri", "")).strip()
    if auth_uri != "https://accounts.google.com/o/oauth2/auth":
        raise MigrationError("OAuth Desktop client JSON has an unexpected auth_uri.")
    if token_uri != "https://oauth2.googleapis.com/token":
        raise MigrationError("OAuth Desktop client JSON has an unexpected token_uri.")
    return client_id, sha256_file(path)


def is_within(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def paths_collide(left: Path, right: Path) -> bool:
    """Conservatively detect aliases, including case-insensitive macOS names."""
    left_resolved = left.resolve(strict=False)
    right_resolved = right.resolve(strict=False)
    if left_resolved == right_resolved:
        return True
    try:
        if left.exists() and right.exists() and os.path.samefile(left, right):
            return True
    except OSError:
        pass
    parent_same = left_resolved.parent == right_resolved.parent
    if not parent_same:
        try:
            parent_same = os.path.samefile(
                left_resolved.parent, right_resolved.parent
            )
        except OSError:
            parent_same = False
    return parent_same and left_resolved.name.casefold() == right_resolved.name.casefold()


def load_profile(path: Path) -> Profile:
    profile_path = path.expanduser().resolve()
    data = load_json(profile_path)
    if data.get("schema_version") != PROFILE_SCHEMA_VERSION:
        raise MigrationError(
            f"Profile schema_version must be {PROFILE_SCHEMA_VERSION}."
        )

    migration_id = str(data.get("migration_id", "")).strip()
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{1,63}", migration_id):
        raise MigrationError(
            "migration_id must be 2-64 lowercase letters, digits, dots, underscores, or hyphens."
        )

    source_root = Path(str(data.get("source_root", ""))).expanduser().resolve()
    state_dir = Path(str(data.get("state_dir", ""))).expanduser().resolve()
    oauth_client = Path(str(data.get("oauth_client", ""))).expanduser().resolve()
    if not source_root.is_dir():
        raise MigrationError(f"Source root is not a directory: {source_root}")
    if not oauth_client.is_file():
        raise MigrationError(f"OAuth Desktop client JSON is missing: {oauth_client}")
    if source_root == state_dir or is_within(state_dir, source_root):
        raise MigrationError("state_dir must be outside the preserved source tree.")

    source_mailbox = normalize_mailbox(data.get("source_mailbox"), "source_mailbox")
    destination = normalize_mailbox(data.get("destination"), "destination")
    oauth_client_id, oauth_client_sha256 = read_oauth_client_config(oauth_client)
    label_prefix = normalize_folder_name(data.get("label_prefix"))
    custom_label_policy = str(
        data.get("custom_label_policy", "archive_prefix_and_folder")
    ).strip()
    if custom_label_policy not in {"archive_prefix_and_folder", "none"}:
        raise MigrationError(
            "custom_label_policy must be 'archive_prefix_and_folder' or 'none'."
        )
    root_folder = normalize_folder_name(data.get("root_folder", "Inbox"))
    inbox_values = data.get("inbox_folders", ["Inbox", "받은편지함"])
    if not isinstance(inbox_values, list) or not inbox_values:
        raise MigrationError("inbox_folders must be a nonempty JSON array.")
    inbox_folders = frozenset(
        normalize_folder_name(item).casefold() for item in inbox_values
    )

    progress_every = int(data.get("progress_every", DEFAULT_PROGRESS_EVERY))
    if progress_every < 1:
        raise MigrationError("progress_every must be at least 1.")

    token_store = data.get("token_store", {"type": "keychain"})
    if not isinstance(token_store, dict):
        raise MigrationError("token_store must be a JSON object.")
    token_store_type = str(token_store.get("type", "keychain")).strip().lower()
    token_file: Path | None = None
    keychain_service = str(
        token_store.get("service", "org.example.gmail-migration-tools")
    ).strip()
    if token_store_type == "file":
        raw_token_file = str(token_store.get("path", "")).strip()
        if not raw_token_file:
            raise MigrationError("A file token_store requires an absolute path.")
        unexpanded_token_file = Path(raw_token_file).expanduser()
        if not unexpanded_token_file.is_absolute():
            raise MigrationError("A file token_store requires an absolute path.")
        token_file = Path(os.path.abspath(unexpanded_token_file))
        if is_within(token_file, source_root):
            raise MigrationError("The OAuth token file cannot be inside the source tree.")
        reserved_token_paths = {
            profile_path,
            oauth_client,
            state_dir,
            state_dir / "manifest.json",
            state_dir / "checkpoint.json",
            state_dir / "checkpoint.json.lock",
            state_dir / "final-report.json",
        }
        if any(paths_collide(token_file, reserved) for reserved in reserved_token_paths):
            raise MigrationError(
                "The OAuth token file path collides with a profile, OAuth client, or "
                "migration state path."
            )
    elif token_store_type == "keychain":
        if not keychain_service:
            raise MigrationError("A keychain token_store requires a service name.")
        if not KEYCHAIN_SECURITY.is_file():
            raise MigrationError(
                "macOS security tool is unavailable; configure a mode-0600 file token_store."
            )
    else:
        raise MigrationError("token_store.type must be 'keychain' or 'file'.")

    rejection_policy = str(data.get("google_rejection_policy", "stop")).strip()
    if rejection_policy not in {"stop", "local_only_known_security_and_continue"}:
        raise MigrationError(
            "google_rejection_policy must be 'stop' or "
            "'local_only_known_security_and_continue'."
        )

    missing_message_id_policy = str(
        data.get("missing_message_id_policy", "stop")
    ).strip()
    if missing_message_id_policy not in MISSING_MESSAGE_ID_POLICIES:
        raise MigrationError(
            "missing_message_id_policy must be 'stop' or "
            "'deterministic_sha256_upload_copy'."
        )

    message_id_collision_policy = str(
        data.get(
            "message_id_collision_policy",
            "stop_on_distinct_prepared_messages",
        )
    ).strip()
    if message_id_collision_policy not in {
        "stop_on_distinct_prepared_messages",
        "import_each_prepared_variant",
    }:
        raise MigrationError(
            "message_id_collision_policy must be "
            "'stop_on_distinct_prepared_messages' or 'import_each_prepared_variant'."
        )

    fingerprint_payload = {
        "schema_version": PROFILE_SCHEMA_VERSION,
        "migration_id": migration_id,
        "source_root": str(source_root),
        "source_mailbox": source_mailbox,
        "destination": destination,
        "state_dir": str(state_dir),
        "oauth_client_id": oauth_client_id,
        "oauth_client_sha256": oauth_client_sha256,
        "required_scopes": list(REQUIRED_SCOPES),
        "label_prefix": label_prefix,
        "custom_label_policy": custom_label_policy,
        "root_folder": root_folder,
        "inbox_folders": sorted(inbox_folders),
        "google_rejection_policy": rejection_policy,
        "missing_message_id_policy": missing_message_id_policy,
        "message_id_collision_policy": message_id_collision_policy,
    }
    profile_fingerprint = sha256_bytes(canonical_json_bytes(fingerprint_payload))
    keychain_account = (
        f"{migration_id}:{destination}:{oauth_client_id}:{oauth_client_sha256[:16]}"
    )

    return Profile(
        path=profile_path,
        migration_id=migration_id,
        source_root=source_root,
        source_mailbox=source_mailbox,
        destination=destination,
        state_dir=state_dir,
        oauth_client=oauth_client,
        oauth_client_id=oauth_client_id,
        oauth_client_sha256=oauth_client_sha256,
        label_prefix=label_prefix,
        custom_label_policy=custom_label_policy,
        root_folder=root_folder,
        inbox_folders=inbox_folders,
        progress_every=progress_every,
        token_store_type=token_store_type,
        token_file=token_file,
        keychain_service=keychain_service,
        keychain_account=keychain_account,
        rejection_policy=rejection_policy,
        missing_message_id_policy=missing_message_id_policy,
        message_id_collision_policy=message_id_collision_policy,
        profile_fingerprint=profile_fingerprint,
    )


def collect_defects(message: Any) -> list[str]:
    defects: list[str] = []
    for part in message.walk():
        defects.extend(type(item).__name__ for item in part.defects)
    return defects


def deterministic_generated_message_id(source_sha256: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{64}", source_sha256):
        raise MigrationError("Cannot generate a Message-ID from an invalid source SHA-256.")
    return f"<cafe24-import-{source_sha256}@migration.invalid>"


def validate_gmail_import_size(size_bytes: int) -> None:
    if (
        not isinstance(size_bytes, int)
        or isinstance(size_bytes, bool)
        or size_bytes < 1
        or size_bytes > GMAIL_IMPORT_MAX_BYTES
    ):
        raise MigrationError(
            "Prepared message size is outside Gmail's 1-byte to 150-MiB import range."
        )


def select_gmail_upload_protocol(prepared: bytes) -> str:
    validate_gmail_import_size(len(prepared))
    # google-api-python-client's multipart builder parses message/rfc822 as a
    # nested email and can fail while ASCII-flattening raw 8-bit header/body
    # bytes. Resumable media uploads preserve those bytes without that local
    # serialization step.
    return (
        GMAIL_UPLOAD_PROTOCOL_SIMPLE
        if prepared.isascii()
        else GMAIL_UPLOAD_PROTOCOL_RESUMABLE
    )


def rfc_header_boundary(value: bytes) -> tuple[int, bytes]:
    candidates: list[tuple[int, bytes]] = []
    crlf_index = value.find(b"\r\n\r\n")
    if crlf_index >= 0:
        candidates.append((crlf_index, b"\r\n"))
    lf_index = value.find(b"\n\n")
    if lf_index >= 0:
        candidates.append((lf_index, b"\n"))
    if not candidates:
        raise MigrationError("Cannot locate the RFC header/body separator.")
    return min(candidates, key=lambda item: item[0])


def insert_rfc_header_before_body(value: bytes, header_line: bytes) -> bytes:
    """Insert one ASCII header without reserializing or refolding the EML."""
    insert_at, newline = rfc_header_boundary(value)
    if b"\r" in header_line or b"\n" in header_line:
        raise MigrationError("Refusing to insert a multiline generated header.")
    return value[:insert_at] + newline + header_line + value[insert_at:]


def replace_single_message_id_header(value: bytes, message_id: str) -> bytes:
    """Replace exactly one top-level Message-ID field in the prepared copy."""
    header_end, _ = rfc_header_boundary(value)
    header_block = value[:header_end]
    matches = list(RFC_MESSAGE_ID_HEADER_BYTES.finditer(header_block))
    if len(matches) != 1:
        raise MigrationError(
            "Expected exactly one raw Message-ID field for deterministic replacement."
        )
    match = matches[0]
    replacement = b"Message-ID: " + message_id.encode("ascii")
    return (
        header_block[: match.start()]
        + replacement
        + header_block[match.end() :]
        + value[header_end:]
    )


def message_id_header_defects(message: Any) -> list[str]:
    return [
        type(defect).__name__
        for header in (message.get_all("Message-ID", []) or [])
        for defect in getattr(header, "defects", ())
    ]


def raw_message_id_values(message: Any) -> list[str]:
    return [
        str(value).strip()
        for name, value in message.raw_items()
        if name.lower() == "message-id"
    ]


def repair_cafe24_received_fold(raw: bytes) -> bytes | None:
    lines = raw.splitlines(keepends=True)
    if (
        len(lines) < 3
        or not lines[0].lower().startswith(b"received:")
        or not CAFE24_RECEIVED_FOLD.match(lines[1])
        or not lines[2].lower().startswith(b"mime-version:")
    ):
        return None
    lines[1] = b" " + lines[1]
    return b"".join(lines)


def repair_cafe24_returned_text_separator(raw: bytes) -> bytes | None:
    matches = list(CAFE24_RETURNED_TEXT_MISSING_SEPARATOR.finditer(raw))
    if len(matches) != 1:
        return None
    insert_at = matches[0].start("body")
    return raw[:insert_at] + b"\r\n" + raw[insert_at:]


def repair_cafe24_empty_boundaryless_related(
    raw: bytes, expected_defect_count: int
) -> tuple[bytes, int] | None:
    matches = list(CAFE24_EMPTY_BOUNDARYLESS_RELATED.finditer(raw))
    if (
        expected_defect_count not in {1, 2}
        or len(matches) != expected_defect_count
    ):
        return None
    prepared = raw
    for match in reversed(matches):
        start, end = match.span(0)
        block = match.group(0)
        repaired_block = block.replace(
            b"Content-Type: multipart/related",
            b"Content-Type: application/octet-stream",
            1,
        )
        prepared = prepared[:start] + repaired_block + prepared[end:]
    return prepared, len(matches)


def prepare_source_bytes(
    raw: bytes,
) -> tuple[bytes, list[str], dict[str, int], list[str]]:
    """Apply only narrowly audited, source-preserving Cafe24 upload repairs."""
    message = BytesParser(policy=policy.default).parsebytes(raw)
    defects = collect_defects(message)
    if not defects:
        return raw, [], {}, []

    prepared: bytes | None = None
    repair_name = ""
    occurrence_count = 0
    before_part_count = sum(1 for _ in message.walk())
    if defects == ["MissingHeaderBodySeparatorDefect"]:
        prepared = repair_cafe24_received_fold(raw)
        if prepared is not None:
            repair_name = REPAIR_CAFE24_RECEIVED_FOLD
            occurrence_count = 1
        else:
            prepared = repair_cafe24_returned_text_separator(raw)
            if prepared is not None:
                repair_name = REPAIR_CAFE24_RETURNED_SEPARATOR
                occurrence_count = 1
    elif defects and set(defects) == {"NoBoundaryInMultipartDefect"}:
        repaired = repair_cafe24_empty_boundaryless_related(raw, len(defects))
        if repaired is not None:
            prepared, occurrence_count = repaired
            repair_name = REPAIR_CAFE24_EMPTY_RELATED

    if prepared is None:
        raise MigrationError(
            f"Unresolved MIME/parser defects do not match an audited Cafe24 repair: {defects}"
        )

    repaired = BytesParser(policy=policy.default).parsebytes(prepared)
    repaired_defects = collect_defects(repaired)
    if repaired_defects:
        raise MigrationError(f"Audited Cafe24 repair left defects: {repaired_defects}")
    if (
        repair_name == REPAIR_CAFE24_EMPTY_RELATED
        and sum(1 for _ in repaired.walk()) != before_part_count
    ):
        raise MigrationError("Audited Cafe24 repair changed the parsed MIME part count.")
    return prepared, [repair_name], {repair_name: occurrence_count}, defects


def parse_source_path(
    path: Path,
    root: Path,
    missing_message_id_policy: str = "stop",
) -> tuple[bytes, dict[str, Any]]:
    if missing_message_id_policy not in MISSING_MESSAGE_ID_POLICIES:
        raise MigrationError("Invalid missing Message-ID policy.")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise MigrationError(f"Cannot read source EML {path}: {exc}") from exc
    raw_sha = sha256_bytes(raw)
    prepared, repairs, repair_occurrences, source_parser_defects = (
        prepare_source_bytes(raw)
    )
    message = BytesParser(policy=policy.default).parsebytes(prepared)
    defects = collect_defects(message)
    if defects:
        raise MigrationError(f"Prepared EML {path} has defects: {defects}")

    source_message_id_headers = message.get_all("Message-ID", []) or []
    source_raw_message_ids = raw_message_id_values(message)
    if len(source_message_id_headers) != len(source_raw_message_ids):
        raise MigrationError(
            f"Source Message-ID parser/raw-header counts differ: {path}"
        )
    if len(source_raw_message_ids) > 1:
        raise MigrationError(f"Source EML has multiple Message-ID headers: {path}")
    source_message_id_defects = message_id_header_defects(message)
    source_message_id = (
        source_raw_message_ids[0] if source_raw_message_ids else ""
    )
    source_message_id_safe = bool(
        RFC_MESSAGE_ID.fullmatch(source_message_id)
        and not source_message_id_defects
    )
    message_id = source_message_id
    message_id_provenance: dict[str, Any] = {
        "kind": "source_header",
        "source_header_count": len(source_raw_message_ids),
    }
    if not source_message_id_safe:
        if missing_message_id_policy != "deterministic_sha256_upload_copy":
            if not source_raw_message_ids:
                raise MigrationError(f"Source EML lacks a safe Message-ID: {path}")
            raise MigrationError(f"Source EML has an unsafe Message-ID: {path}")
        message_id = deterministic_generated_message_id(raw_sha)
        source_header_state = (
            "missing" if not source_raw_message_ids else "invalid_single_header"
        )
        if source_raw_message_ids:
            prepared = replace_single_message_id_header(prepared, message_id)
        else:
            prepared = insert_rfc_header_before_body(
                prepared,
                b"Message-ID: " + message_id.encode("ascii"),
            )
        message = BytesParser(policy=policy.default).parsebytes(prepared)
        defects = collect_defects(message)
        generated_headers = message.get_all("Message-ID", [])
        if (
            defects
            or len(generated_headers) != 1
            or raw_message_id_values(message) != [message_id]
            or message_id_header_defects(message)
        ):
            raise MigrationError(
                f"Deterministic Message-ID upload-copy repair failed validation: {path}"
            )
        repairs.append(REPAIR_GENERATED_MESSAGE_ID)
        repair_occurrences[REPAIR_GENERATED_MESSAGE_ID] = 1
        message_id_provenance = {
            "kind": "deterministic_sha256_upload_copy",
            "source_header_count": len(source_raw_message_ids),
            "source_header_state": source_header_state,
            "source_header_value": source_message_id or None,
            "source_header_defects": source_message_id_defects,
            "generated_from": "source_sha256",
            "generated_value": message_id,
        }

    date_header = str(message.get("Date", "")).strip()
    if not RFC_MESSAGE_ID.fullmatch(message_id):
        raise MigrationError(f"Source EML lacks a safe Message-ID: {path}")
    if not date_header:
        raise MigrationError(f"Source EML lacks a Date header: {path}")
    try:
        parsed_date = parsedate_to_datetime(date_header)
    except (TypeError, ValueError, OverflowError) as exc:
        raise MigrationError(f"Source EML has an invalid Date header: {path}") from exc
    date_policy = "rfc5322_offset"
    if parsed_date.tzinfo is None:
        if date_header.endswith("-0000"):
            parsed_date = parsed_date.replace(tzinfo=timezone.utc)
            date_policy = "rfc5322_minus0000_preserved_interpreted_as_utc"
        else:
            raise MigrationError(f"Source Date has no timezone: {path}")

    relative_path = path.relative_to(root).as_posix()
    item_key = sha256_bytes((relative_path + "\0" + raw_sha).encode("utf-8"))
    return prepared, {
        "item_key": item_key,
        "relative_path": relative_path,
        "source_size_bytes": len(raw),
        "source_sha256": raw_sha,
        "prepared_size_bytes": len(prepared),
        "prepared_sha256": sha256_bytes(prepared),
        "repairs": repairs,
        "repair_occurrences": repair_occurrences,
        "source_parser_defects": source_parser_defects,
        "message_id": message_id,
        "message_id_provenance": message_id_provenance,
        "date_header": date_header,
        "expected_internal_date_ms": int(parsed_date.timestamp() * 1000),
        "date_policy": date_policy,
        "subject": str(message.get("Subject", "")).strip(),
        "from": str(message.get("From", "")).strip(),
        "to": str(message.get("To", "")).strip(),
        "cc": str(message.get("Cc", "")).strip(),
    }


def discover_eml_files(root: Path) -> list[Path]:
    paths = [path for path in root.rglob("*") if path.is_file() and path.suffix.lower() == ".eml"]
    paths.sort(key=lambda item: (item.relative_to(root).as_posix().casefold(), item.relative_to(root).as_posix()))
    if not paths:
        raise MigrationError(f"No .eml files were found below {root}.")
    return paths


def source_folder_for(profile: Profile, relative_path: str) -> str:
    parent = Path(relative_path).parent.as_posix()
    return profile.root_folder if parent == "." else normalize_folder_name(parent)


def label_names_for(profile: Profile, source_folder: str) -> list[str]:
    if profile.custom_label_policy == "none":
        return []
    names = [profile.label_prefix]
    folder_label = f"{profile.label_prefix}/{source_folder}"
    if folder_label != profile.label_prefix:
        names.append(folder_label)
    return names


def build_manifest(profile: Profile) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    errors: list[str] = []
    for path in discover_eml_files(profile.source_root):
        try:
            _, row = parse_source_path(
                path, profile.source_root, profile.missing_message_id_policy
            )
        except MigrationError as exc:
            errors.append(str(exc))
            continue
        source_folder = source_folder_for(profile, row["relative_path"])
        row["source_folder"] = source_folder
        row["target_label_names"] = label_names_for(profile, source_folder)
        row["target_system_label_ids"] = (
            ["INBOX"] if source_folder.casefold() in profile.inbox_folders else []
        )
        rows.append(row)
    if errors:
        preview = "\n".join(f"- {item}" for item in errors[:20])
        extra = "" if len(errors) <= 20 else f"\n- ... {len(errors) - 20} more"
        raise MigrationError(
            f"Manifest preparation found {len(errors)} unsafe/unparseable EML files:\n"
            f"{preview}{extra}"
        )

    # One byte-equivalent message found in more than one exported folder is one
    # Gmail message with the union of those folder labels.  Importing every
    # physical copy would either create a duplicate or let Gmail return the
    # canonical ID twice, neither of which proves folder coverage.
    exact_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        row["action"] = "import"
        exact_groups[str(row["prepared_sha256"])].append(row)
    exact_duplicate_groups: list[dict[str, Any]] = []
    for prepared_sha256, members in sorted(exact_groups.items()):
        if len(members) < 2:
            continue
        members.sort(key=lambda item: (item["relative_path"].casefold(), item["relative_path"]))
        canonical = members[0]
        union_custom = sorted(
            {name for member in members for name in member["target_label_names"]},
            key=lambda value: (value.casefold(), value),
        )
        union_system = sorted(
            {name for member in members for name in member["target_system_label_ids"]}
        )
        canonical["target_label_names"] = union_custom
        canonical["target_system_label_ids"] = union_system
        canonical["represented_source_item_keys"] = [
            member["item_key"] for member in members
        ]
        for duplicate in members[1:]:
            duplicate["action"] = "merge_exact_duplicate"
            duplicate["represented_by_item_key"] = canonical["item_key"]
        exact_duplicate_groups.append(
            {
                "prepared_sha256": prepared_sha256,
                "canonical_item_key": canonical["item_key"],
                "member_item_keys": [member["item_key"] for member in members],
                "member_relative_paths": [member["relative_path"] for member in members],
                "union_target_label_names": union_custom,
                "union_target_system_label_ids": union_system,
            }
        )

    by_message_id: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_message_id[str(row["message_id"])].append(row)
    distinct_prepared_collisions = [
        {
            "message_id": message_id,
            "prepared_sha256_values": sorted(
                {str(member["prepared_sha256"]) for member in members}
            ),
            "member_item_keys": [member["item_key"] for member in members],
            "member_relative_paths": [member["relative_path"] for member in members],
        }
        for message_id, members in sorted(by_message_id.items())
        if len({str(member["prepared_sha256"]) for member in members}) > 1
    ]
    if (
        distinct_prepared_collisions
        and profile.message_id_collision_policy
        == "stop_on_distinct_prepared_messages"
    ):
        preview = "; ".join(
            f"{group['message_id']} -> {group['member_relative_paths']}"
            for group in distinct_prepared_collisions[:10]
        )
        raise MigrationError(
            "Distinct prepared EMLs share a Message-ID. Review the source or explicitly set "
            "message_id_collision_policy='import_each_prepared_variant' before preparing. "
            f"Collisions: {preview}"
        )

    message_id_counts = Counter(row["message_id"] for row in rows)
    duplicate_groups = {
        message_id: count
        for message_id, count in sorted(message_id_counts.items())
        if count > 1
    }
    total_bytes = sum(int(row["source_size_bytes"]) for row in rows)
    prepared_bytes = sum(int(row["prepared_size_bytes"]) for row in rows)
    repair_counts = Counter(
        repair for row in rows for repair in row.get("repairs", [])
    )
    repair_occurrence_counts = Counter(
        repair
        for row in rows
        for repair, count in row.get("repair_occurrences", {}).items()
        for _ in range(int(count))
    )
    generated_message_id_rows = sum(
        row.get("message_id_provenance", {}).get("kind")
        == "deterministic_sha256_upload_copy"
        for row in rows
    )
    manifest = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "migration_id": profile.migration_id,
        "created_at": utc_now(),
        "profile_fingerprint": profile.profile_fingerprint,
        "source_mailbox": profile.source_mailbox,
        "source_root": str(profile.source_root),
        "expected_destination": profile.destination,
        "oauth_client_id": profile.oauth_client_id,
        "oauth_client_sha256": profile.oauth_client_sha256,
        "required_scopes": list(REQUIRED_SCOPES),
        "custom_label_policy": profile.custom_label_policy,
        "missing_message_id_policy": profile.missing_message_id_policy,
        "source_eml_count": len(rows),
        "source_total_bytes": total_bytes,
        "prepared_total_bytes": prepared_bytes,
        "folder_counts": dict(Counter(row["source_folder"] for row in rows)),
        "duplicate_message_id_groups": duplicate_groups,
        "exact_prepared_duplicate_groups": exact_duplicate_groups,
        "exact_prepared_duplicate_source_rows": sum(
            len(group["member_item_keys"]) - 1 for group in exact_duplicate_groups
        ),
        "unique_gmail_upload_rows": sum(
            row["action"] == "import" for row in rows
        ),
        "distinct_prepared_message_id_collisions": distinct_prepared_collisions,
        "message_id_collision_policy": profile.message_id_collision_policy,
        "temporary_repair_counts": dict(repair_counts),
        "temporary_repair_occurrence_counts": dict(repair_occurrence_counts),
        "generated_message_id_source_rows": generated_message_id_rows,
        "source_files_modified": 0,
        "messages": rows,
    }
    manifest["inventory_sha256"] = sha256_bytes(canonical_json_bytes(rows))
    return manifest


def command_prepare(profile: Profile, replace: bool) -> int:
    if profile.checkpoint_path.exists():
        raise MigrationError(
            "Refusing to replace or rebuild a manifest after a checkpoint exists."
        )
    if profile.manifest_path.exists() and not replace:
        raise MigrationError(
            f"Manifest already exists: {profile.manifest_path}; use --replace only before execution."
        )
    manifest = build_manifest(profile)
    write_json_atomic(profile.manifest_path, manifest)
    print("prepare: PASS")
    print("source_eml_count:", manifest["source_eml_count"])
    print("source_total_bytes:", manifest["source_total_bytes"])
    print("folders:", len(manifest["folder_counts"]))
    print("duplicate_message_id_groups:", len(manifest["duplicate_message_id_groups"]))
    print("exact_prepared_duplicate_source_rows:", manifest["exact_prepared_duplicate_source_rows"])
    print("unique_gmail_upload_rows:", manifest["unique_gmail_upload_rows"])
    print("generated_message_id_source_rows:", manifest["generated_message_id_source_rows"])
    print(
        "distinct_prepared_message_id_collisions:",
        len(manifest["distinct_prepared_message_id_collisions"]),
    )
    print("manifest_sha256:", sha256_file(profile.manifest_path))
    print("gmail_writes_this_run: 0")
    return 0


def load_manifest(profile: Profile) -> dict[str, Any]:
    if not profile.manifest_path.is_file():
        raise MigrationError(
            f"Manifest is missing; run prepare first: {profile.manifest_path}"
        )
    manifest = load_json(profile.manifest_path)
    expected = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "migration_id": profile.migration_id,
        "profile_fingerprint": profile.profile_fingerprint,
        "source_mailbox": profile.source_mailbox,
        "source_root": str(profile.source_root),
        "expected_destination": profile.destination,
        "oauth_client_id": profile.oauth_client_id,
        "oauth_client_sha256": profile.oauth_client_sha256,
        "required_scopes": list(REQUIRED_SCOPES),
        "custom_label_policy": profile.custom_label_policy,
        "missing_message_id_policy": profile.missing_message_id_policy,
    }
    for field, value in expected.items():
        if manifest.get(field) != value:
            raise MigrationError(f"Manifest field {field} no longer matches the profile.")
    rows = manifest.get("messages")
    if not isinstance(rows, list) or not rows:
        raise MigrationError("Manifest messages must be a nonempty array.")
    if manifest.get("source_eml_count") != len(rows):
        raise MigrationError("Manifest source count does not match its message rows.")
    if manifest.get("inventory_sha256") != sha256_bytes(canonical_json_bytes(rows)):
        raise MigrationError("Manifest inventory hash is invalid.")
    item_keys = [str(row.get("item_key", "")) for row in rows]
    relative_paths = [str(row.get("relative_path", "")) for row in rows]
    if len(set(item_keys)) != len(rows) or "" in item_keys:
        raise MigrationError("Manifest item keys are missing or duplicated.")
    if len(set(relative_paths)) != len(rows) or "" in relative_paths:
        raise MigrationError("Manifest relative paths are missing or duplicated.")
    rows_by_key = {str(row["item_key"]): row for row in rows}
    for row in rows:
        repairs = row.get("repairs")
        repair_occurrences = row.get("repair_occurrences")
        source_parser_defects = row.get("source_parser_defects")
        provenance = row.get("message_id_provenance")
        if not isinstance(repairs, list) or not all(
            isinstance(item, str) and item for item in repairs
        ):
            raise MigrationError("Manifest repair provenance is invalid.")
        if not isinstance(repair_occurrences, dict) or any(
            repair not in repairs
            or not isinstance(count, int)
            or isinstance(count, bool)
            or count < 1
            for repair, count in repair_occurrences.items()
        ):
            raise MigrationError("Manifest repair occurrence evidence is invalid.")
        if not isinstance(source_parser_defects, list) or not all(
            isinstance(item, str) and item for item in source_parser_defects
        ):
            raise MigrationError("Manifest source parser-defect evidence is invalid.")
        if not isinstance(provenance, dict):
            raise MigrationError("Manifest Message-ID provenance is invalid.")
        provenance_kind = provenance.get("kind")
        if provenance_kind == "source_header":
            if (
                provenance.get("source_header_count") != 1
                or REPAIR_GENERATED_MESSAGE_ID in repairs
            ):
                raise MigrationError("Source Message-ID provenance is inconsistent.")
        elif provenance_kind == "deterministic_sha256_upload_copy":
            expected_generated = deterministic_generated_message_id(
                str(row.get("source_sha256", ""))
            )
            source_header_state = provenance.get("source_header_state")
            source_header_count = provenance.get("source_header_count")
            source_header_value = provenance.get("source_header_value")
            source_header_defects = provenance.get("source_header_defects")
            if not isinstance(source_header_defects, list) or not all(
                isinstance(item, str) and item for item in source_header_defects
            ):
                raise MigrationError("Generated Message-ID provenance is inconsistent.")
            missing_source_header = (
                source_header_state == "missing"
                and source_header_count == 0
                and source_header_value is None
                and source_header_defects == []
            )
            invalid_source_header = (
                source_header_state == "invalid_single_header"
                and source_header_count == 1
                and isinstance(source_header_value, str)
                and bool(source_header_value)
                and (
                    not RFC_MESSAGE_ID.fullmatch(source_header_value)
                    or bool(source_header_defects)
                )
            )
            if (
                profile.missing_message_id_policy
                != "deterministic_sha256_upload_copy"
                or not (missing_source_header or invalid_source_header)
                or provenance.get("generated_from") != "source_sha256"
                or provenance.get("generated_value") != expected_generated
                or row.get("message_id") != expected_generated
                or repairs.count(REPAIR_GENERATED_MESSAGE_ID) != 1
                or repair_occurrences.get(REPAIR_GENERATED_MESSAGE_ID) != 1
            ):
                raise MigrationError("Generated Message-ID provenance is inconsistent.")
        else:
            raise MigrationError("Manifest Message-ID provenance kind is invalid.")
        action = row.get("action")
        if action not in {"import", "merge_exact_duplicate"}:
            raise MigrationError(
                f"Manifest action is invalid for {row.get('relative_path')}."
            )
        if action == "merge_exact_duplicate":
            canonical_key = str(row.get("represented_by_item_key", ""))
            canonical = rows_by_key.get(canonical_key)
            if canonical is None or canonical.get("action") != "import":
                raise MigrationError("Exact duplicate has no valid canonical manifest row.")
            if canonical.get("prepared_sha256") != row.get("prepared_sha256"):
                raise MigrationError("Exact duplicate differs from its canonical prepared hash.")
            if row["item_key"] not in canonical.get("represented_source_item_keys", []):
                raise MigrationError("Canonical duplicate membership is incomplete.")
    if manifest.get("unique_gmail_upload_rows") != sum(
        row.get("action") == "import" for row in rows
    ):
        raise MigrationError("Manifest unique Gmail upload count is invalid.")
    expected_repair_counts = dict(
        Counter(repair for row in rows for repair in row.get("repairs", []))
    )
    expected_repair_occurrences = dict(
        Counter(
            {
                repair: sum(
                    int(row.get("repair_occurrences", {}).get(repair, 0))
                    for row in rows
                )
                for repair in {
                    name
                    for row in rows
                    for name in row.get("repair_occurrences", {})
                }
            }
        )
    )
    if manifest.get("temporary_repair_counts") != expected_repair_counts:
        raise MigrationError("Manifest repair-row counts are invalid.")
    if (
        manifest.get("temporary_repair_occurrence_counts")
        != expected_repair_occurrences
    ):
        raise MigrationError("Manifest repair occurrence counts are invalid.")
    expected_generated_rows = sum(
        row.get("message_id_provenance", {}).get("kind")
        == "deterministic_sha256_upload_copy"
        for row in rows
    )
    if manifest.get("generated_message_id_source_rows") != expected_generated_rows:
        raise MigrationError("Manifest generated Message-ID count is invalid.")
    return manifest


def validate_source_snapshot(profile: Profile, manifest: dict[str, Any]) -> None:
    paths = discover_eml_files(profile.source_root)
    rows = manifest["messages"]
    if len(paths) != len(rows):
        raise MigrationError(
            f"Source inventory changed: expected {len(rows)} EML files, found {len(paths)}."
        )
    paths_by_relative = {
        path.relative_to(profile.source_root).as_posix(): path for path in paths
    }
    expected_fields = (
        "item_key",
        "relative_path",
        "source_size_bytes",
        "source_sha256",
        "prepared_size_bytes",
        "prepared_sha256",
        "repairs",
        "repair_occurrences",
        "source_parser_defects",
        "message_id",
        "message_id_provenance",
        "date_header",
        "expected_internal_date_ms",
        "date_policy",
        "subject",
        "from",
        "to",
        "cc",
    )
    for row in rows:
        relative = str(row["relative_path"])
        path = paths_by_relative.get(relative)
        if path is None:
            raise MigrationError(f"Source file is missing: {relative}")
        _, observed = parse_source_path(
            path, profile.source_root, profile.missing_message_id_policy
        )
        for field in expected_fields:
            if observed.get(field) != row.get(field):
                raise MigrationError(f"Source drift in {relative}: field {field} changed.")
    total_bytes = sum(path.stat().st_size for path in paths)
    if total_bytes != int(manifest.get("source_total_bytes", -1)):
        raise MigrationError("Source total bytes changed after manifest preparation.")


def new_checkpoint(profile: Profile, manifest: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": CHECKPOINT_SCHEMA_VERSION,
        "migration_id": profile.migration_id,
        "destination": profile.destination,
        "profile_fingerprint": profile.profile_fingerprint,
        "manifest_sha256": sha256_file(profile.manifest_path),
        "created_at": utc_now(),
        "updated_at": utc_now(),
        "gmail_labels": {},
        "states": {
            row["item_key"]: {
                "status": (
                    "duplicate_pending_canonical"
                    if row.get("action") == "merge_exact_duplicate"
                    else "pending"
                ),
                "relative_path": row["relative_path"],
                "source_sha256": row["source_sha256"],
                "prepared_sha256": row["prepared_sha256"],
                "message_id": row["message_id"],
                **(
                    {"represented_by_item_key": row["represented_by_item_key"]}
                    if row.get("action") == "merge_exact_duplicate"
                    else {}
                ),
                "review_history": [],
            }
            for row in manifest["messages"]
        },
    }


def load_checkpoint(
    profile: Profile, manifest: dict[str, Any], create: bool = False
) -> dict[str, Any]:
    if not profile.checkpoint_path.exists():
        if not create:
            raise MigrationError("Checkpoint does not exist; the migration has not run.")
        return new_checkpoint(profile, manifest)
    checkpoint = load_json(profile.checkpoint_path)
    expected = {
        "schema_version": CHECKPOINT_SCHEMA_VERSION,
        "migration_id": profile.migration_id,
        "destination": profile.destination,
        "profile_fingerprint": profile.profile_fingerprint,
        "manifest_sha256": sha256_file(profile.manifest_path),
    }
    for field, value in expected.items():
        if checkpoint.get(field) != value:
            raise MigrationError(f"Checkpoint field {field} does not match the active migration.")
    states = checkpoint.get("states")
    expected_rows = {row["item_key"]: row for row in manifest["messages"]}
    if not isinstance(states, dict) or set(states) != set(expected_rows):
        raise MigrationError("Checkpoint keys do not exactly match the manifest.")
    seen_gmail_ids: dict[str, str] = {}
    for item_key, row in expected_rows.items():
        state = states[item_key]
        if not isinstance(state, dict):
            raise MigrationError(f"Checkpoint state is invalid for {item_key}.")
        if state.get("relative_path") != row["relative_path"]:
            raise MigrationError(f"Checkpoint path changed for {item_key}.")
        if state.get("source_sha256") != row["source_sha256"]:
            raise MigrationError(f"Checkpoint source hash changed for {item_key}.")
        if state.get("prepared_sha256") != row["prepared_sha256"]:
            raise MigrationError(f"Checkpoint prepared hash changed for {item_key}.")
        if state.get("message_id") != row["message_id"]:
            raise MigrationError(f"Checkpoint Message-ID changed for {item_key}.")
        if not isinstance(state.get("review_history"), list):
            raise MigrationError(f"Checkpoint review history is invalid for {item_key}.")
        status_value = state.get("status")
        if status_value not in KNOWN_STATUSES:
            raise MigrationError(f"Unknown checkpoint status {status_value!r} for {item_key}.")
        upload_protocol = state.get("last_attempted_upload_protocol")
        upload_size = state.get("last_attempted_upload_size_bytes")
        if upload_protocol is not None or upload_size is not None:
            if upload_protocol not in GMAIL_UPLOAD_PROTOCOLS:
                raise MigrationError(f"Checkpoint upload protocol is invalid for {item_key}.")
            try:
                validate_gmail_import_size(upload_size)
            except MigrationError as exc:
                raise MigrationError(
                    f"Checkpoint upload size is invalid for {item_key}."
                ) from exc
        gmail_id = str(state.get("gmail_message_id", ""))
        if gmail_id:
            other = seen_gmail_ids.get(gmail_id)
            if other is not None and other != item_key:
                raise MigrationError(
                    f"Gmail message ID {gmail_id} is claimed by two source rows."
                )
            seen_gmail_ids[gmail_id] = item_key

        if status_value in {
            "pending",
            "duplicate_pending_canonical",
            "inflight",
            "uncertain",
            "google_rejected",
            "preexisting_conflict",
            "local_only_reviewed",
            "duplicate_source_reviewed",
            "duplicate_local_only_reviewed",
        } and gmail_id:
            raise MigrationError(
                f"Checkpoint status {status_value} must not claim a Gmail ID for {item_key}."
            )
        if status_value == "duplicate_pending_canonical":
            if (
                row.get("action") != "merge_exact_duplicate"
                or state.get("represented_by_item_key")
                != row.get("represented_by_item_key")
            ):
                raise MigrationError(f"Duplicate canonical mapping is invalid for {item_key}.")
        if status_value == "inflight" and (
            not state.get("attempted_at")
            or not state.get("attempted_prepared_sha256")
        ):
            raise MigrationError(f"Inflight evidence is incomplete for {item_key}.")
        if status_value == "uncertain" and not (
            state.get("error")
            or state.get("error_type")
            or state.get("reconciliation_observations")
            or state.get("http_status")
        ):
            raise MigrationError(f"Uncertain outcome has no evidence for {item_key}.")
        if status_value == "google_rejected" and (
            not state.get("google_error_fingerprint")
            or state.get("source_preserved") is not True
        ):
            raise MigrationError(f"Google rejection evidence is incomplete for {item_key}.")
        if status_value == "preexisting_conflict" and not state.get(
            "preexisting_gmail_ids"
        ):
            raise MigrationError(f"Preexisting conflict has no candidates for {item_key}.")
        if status_value in {
            "imported_pending_verification",
            "preexisting_pending_verification",
            "candidate_pending_verification",
        } and not gmail_id:
            raise MigrationError(f"Pending verification has no Gmail ID for {item_key}.")
        if status_value == "review_required" and not (
            state.get("readback_issues") or state.get("error")
        ):
            raise MigrationError(f"Review-required state has no review evidence for {item_key}.")
        if status_value == "verified" and (
            not gmail_id
            or not state.get("verified_at")
            or state.get("readback_issues") != []
            or not state.get("verified_prepared_sha256")
        ):
            raise MigrationError(f"Verified evidence is incomplete for {item_key}.")
        if status_value == "preexisting_reviewed" and (
            not gmail_id
            or not state.get("verified_at")
            or state.get("readback_issues") != []
            or not state.get("review_history")
        ):
            raise MigrationError(f"Preexisting review evidence is incomplete for {item_key}.")
        if status_value == "verified_manual" and (
            not gmail_id
            or not state.get("verified_at")
            or not state.get("decision_reason")
            or not state.get("review_history")
        ):
            raise MigrationError(f"Manual verification evidence is incomplete for {item_key}.")
        if status_value == "local_only_reviewed" and (
            state.get("source_preserved") is not True
            or not state.get("decision_reason")
            or not (
                state.get("google_error_fingerprint")
                or state.get("conflicting_gmail_message_id")
                or state.get("resolved_final_reconciliation_failure")
            )
        ):
            raise MigrationError(f"Local-only review evidence is incomplete for {item_key}.")
        if status_value == "duplicate_source_reviewed" and (
            row.get("action") != "merge_exact_duplicate"
            or state.get("represented_by_item_key")
            != row.get("represented_by_item_key")
            or not state.get("represented_by_gmail_id")
            or state.get("represented_prepared_sha256") != row.get("prepared_sha256")
            or not state.get("verified_at")
        ):
            raise MigrationError(f"Exact-duplicate coverage evidence is incomplete for {item_key}.")
        if status_value == "duplicate_local_only_reviewed" and (
            row.get("action") != "merge_exact_duplicate"
            or state.get("represented_by_item_key")
            != row.get("represented_by_item_key")
            or state.get("source_preserved") is not True
            or not state.get("decision_reason")
            or not state.get("verified_at")
        ):
            raise MigrationError(
                f"Exact-duplicate local-only evidence is incomplete for {item_key}."
            )
        if row.get("action") == "merge_exact_duplicate" and status_value not in {
            "duplicate_pending_canonical",
            "duplicate_source_reviewed",
            "duplicate_local_only_reviewed",
        }:
            raise MigrationError(
                f"Exact-duplicate row has an incompatible status for {item_key}."
            )
        if row.get("action") == "import" and status_value in {
            "duplicate_pending_canonical",
            "duplicate_source_reviewed",
            "duplicate_local_only_reviewed",
        }:
            raise MigrationError(f"Canonical/import row has a duplicate-only status for {item_key}.")

    for item_key, row in expected_rows.items():
        state = states[item_key]
        if state.get("status") != "duplicate_source_reviewed":
            continue
        canonical_key = str(state["represented_by_item_key"])
        canonical = states.get(canonical_key)
        if (
            canonical is None
            or canonical.get("status") != "verified"
            or state.get("represented_by_gmail_id")
            != canonical.get("gmail_message_id")
            or canonical.get("verified_prepared_sha256")
            != row.get("prepared_sha256")
            or not set(state.get("canonical_union_label_ids", [])).issubset(
                {str(value) for value in canonical.get("returned_label_ids", [])}
            )
        ):
            raise MigrationError(
                f"Exact-duplicate canonical evidence is no longer valid for {item_key}."
            )
    return checkpoint


def save_checkpoint(profile: Profile, checkpoint: dict[str, Any]) -> None:
    checkpoint["updated_at"] = utc_now()
    write_json_atomic(profile.checkpoint_path, checkpoint)


def save_state(
    profile: Profile,
    checkpoint: dict[str, Any],
    item_key: str,
    **updates: Any,
) -> None:
    checkpoint["states"][item_key].update(updates)
    save_checkpoint(profile, checkpoint)


@contextmanager
def exclusive_checkpoint_lock(checkpoint_path: Path):
    lock_path = checkpoint_path.with_name(checkpoint_path.name + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with lock_path.open("a+", encoding="utf-8") as handle:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise MigrationError(
                "Another process is already using this migration checkpoint."
            ) from exc
        handle.seek(0)
        handle.truncate()
        handle.write(f"pid={os.getpid()} locked_at={utc_now()}\n")
        handle.flush()
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def token_store_description(profile: Profile) -> str:
    if profile.token_store_type == "keychain":
        return f"macOS Keychain service={profile.keychain_service} account={profile.keychain_account}"
    return f"mode-0600 file={profile.token_file}"


def load_token_json(profile: Profile) -> str | None:
    if profile.token_store_type == "file":
        assert profile.token_file is not None
        if not profile.token_file.exists():
            return None
        if profile.token_file.is_symlink() or not profile.token_file.is_file():
            raise MigrationError("OAuth token path must be a regular, non-symlink file.")
        token_stat = profile.token_file.stat()
        if token_stat.st_uid != os.getuid():
            raise MigrationError("OAuth token file is not owned by the current user.")
        mode = stat.S_IMODE(token_stat.st_mode)
        if mode & 0o077:
            raise MigrationError(
                f"OAuth token file permissions are {oct(mode)}; expected 0o600."
            )
        return profile.token_file.read_text(encoding="utf-8")

    try:
        result = subprocess.run(
            [
                str(KEYCHAIN_SECURITY),
                "find-generic-password",
                "-a",
                profile.keychain_account,
                "-s",
                profile.keychain_service,
                "-w",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    except subprocess.TimeoutExpired as exc:
        raise MigrationError(
            "Timed out while reading OAuth credentials from macOS Keychain."
        ) from exc
    if result.returncode == 0:
        return result.stdout.rstrip("\n")
    stderr = result.stderr.lower()
    if result.returncode == 44 or "could not be found" in stderr:
        return None
    raise MigrationError("Could not read the OAuth credential from macOS Keychain.")


def save_token_json(profile: Profile, token_json: str) -> None:
    try:
        parsed = json.loads(token_json)
    except json.JSONDecodeError as exc:
        raise MigrationError("Refusing to store an invalid OAuth credential JSON value.") from exc
    if not isinstance(parsed, dict) or not parsed.get("refresh_token"):
        raise MigrationError("Refusing to store OAuth credentials without a refresh token.")
    parsed["_migration_binding"] = {
        "destination": profile.destination,
        "oauth_client_id": profile.oauth_client_id,
        "oauth_client_sha256": profile.oauth_client_sha256,
        "required_scopes": list(REQUIRED_SCOPES),
    }
    compact_token_json = json.dumps(
        parsed, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )

    if profile.token_store_type == "file":
        assert profile.token_file is not None
        write_json_atomic(profile.token_file, parsed, mode=0o600)
        return

    # Feed an interactive Keychain command on stdin.  Supplying ``-w`` without
    # a value opens /dev/tty on current macOS releases, while supplying its
    # value directly would expose the refresh token in the process argv.
    # ``-X`` accepts bytes as hex; the command itself travels only through the
    # child's stdin and the token is never placed in argv or printed.
    keychain_command = (
        "add-generic-password -U"
        f" -a {shlex.quote(profile.keychain_account)}"
        f" -s {shlex.quote(profile.keychain_service)}"
        f" -X {compact_token_json.encode('utf-8').hex()}\n"
    )
    try:
        result = subprocess.run(
            [str(KEYCHAIN_SECURITY), "-q", "-i"],
            input=keychain_command,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    except subprocess.TimeoutExpired as exc:
        raise MigrationError("Timed out while saving OAuth credentials to Keychain.") from exc
    if result.returncode != 0:
        raise MigrationError(
            "Could not save OAuth credentials to macOS Keychain; configure the documented "
            "mode-0600 file fallback if this Mac blocks noninteractive Keychain writes."
        )
    stored = load_token_json(profile)
    if stored != compact_token_json:
        raise MigrationError(
            "Could not verify the OAuth credential after saving it to macOS Keychain."
        )


def google_dependencies() -> dict[str, Any]:
    try:
        from google.auth.transport.requests import Request as GoogleAuthRequest
        from google.oauth2.credentials import Credentials
        from google_auth_oauthlib.flow import InstalledAppFlow
        from googleapiclient.discovery import build
        from googleapiclient.errors import HttpError
        from googleapiclient.http import MediaIoBaseUpload
    except ImportError as exc:
        raise MigrationError(
            "Google API libraries are missing. Install the versions in "
            "requirements-gmail-eml-migration.txt."
        ) from exc
    return {
        "GoogleAuthRequest": GoogleAuthRequest,
        "Credentials": Credentials,
        "InstalledAppFlow": InstalledAppFlow,
        "build": build,
        "HttpError": HttpError,
        "MediaIoBaseUpload": MediaIoBaseUpload,
    }


def build_gmail_service(credentials: Any, dependencies: dict[str, Any]) -> Any:
    return dependencies["build"](
        "gmail", "v1", credentials=credentials, cache_discovery=False
    )


def verify_exact_account(service: Any, expected: str) -> str:
    try:
        result = service.users().getProfile(userId="me").execute(num_retries=3)
    except Exception as exc:
        status_code, reasons, _ = http_error_details(exc)
        if status_code == 401 or bool(set(reasons) & AUTH_ERROR_REASONS):
            raise AuthRequired(
                "Google rejected the stored grant while verifying the Gmail account."
            ) from exc
        if status_code == 403:
            raise MigrationError(
                "Google policy or quota blocked the account check; the stored grant was "
                f"preserved (reasons={reasons or ['unspecified_403']})."
            ) from exc
        raise MigrationError(
            "Temporarily unable to verify the Gmail account; the stored grant was preserved."
        ) from exc
    actual = str(result.get("emailAddress", "")).strip().lower()
    if actual != expected:
        raise AuthRequired(
            f"Authorized account is {actual or '(unavailable)'}, expected {expected}."
        )
    return actual


def command_authorize(profile: Profile, reauthorize: bool) -> int:
    existing = load_token_json(profile)
    if existing is not None and not reauthorize:
        raise MigrationError(
            "A persisted authorization already exists. Use --reauthorize only when the "
            "grant was revoked or the profile scopes intentionally changed."
        )
    dependencies = google_dependencies()
    flow = dependencies["InstalledAppFlow"].from_client_secrets_file(
        str(profile.oauth_client), scopes=REQUIRED_SCOPES
    )
    flow.run_local_server(
        port=0,
        open_browser=True,
        access_type="offline",
        prompt="consent select_account",
        login_hint=profile.destination,
        authorization_prompt_message="AUTH_URL: {url}",
        success_message=(
            "OAuth finished. Return to Terminal; the migration tool will verify the "
            "exact account before storing the offline authorization."
        ),
    )
    credentials = flow.credentials
    if not credentials.refresh_token:
        raise AuthRequired(
            "Google did not return a refresh token. Confirm the app is Internal/In production, "
            "then run authorize --reauthorize."
        )
    token_granted_scopes = normalize_scope_values(
        flow.oauth2session.token.get("scope", ())
    )
    if not token_granted_scopes:
        token_granted_scopes = normalize_scope_values(
            getattr(credentials, "granted_scopes", None)
            or getattr(credentials, "scopes", None)
        )
    if not set(REQUIRED_SCOPES).issubset(token_granted_scopes):
        raise AuthRequired("Google did not grant every required migration scope.")
    service = build_gmail_service(credentials, dependencies)
    actual = verify_exact_account(service, profile.destination)
    save_token_json(profile, credentials.to_json())
    print("authorization: STORED")
    print("authorized_email:", actual)
    print("exact_account_match: true")
    print("token_store:", token_store_description(profile))
    print("refresh_token_printed: false")
    return 0


def load_authorized_credentials(profile: Profile) -> tuple[Any, Any, dict[str, Any]]:
    token_json = load_token_json(profile)
    if token_json is None:
        raise AuthRequired(
            "No stored offline authorization; run the authorize command once."
        )
    try:
        info = json.loads(token_json)
    except json.JSONDecodeError as exc:
        raise AuthRequired("Stored OAuth credential is invalid JSON.") from exc
    if not isinstance(info, dict):
        raise AuthRequired("Stored OAuth credential has the wrong shape.")
    expected_binding = {
        "destination": profile.destination,
        "oauth_client_id": profile.oauth_client_id,
        "oauth_client_sha256": profile.oauth_client_sha256,
        "required_scopes": list(REQUIRED_SCOPES),
    }
    if info.get("_migration_binding") != expected_binding:
        raise AuthRequired(
            "Stored OAuth credential is not bound to this mailbox and OAuth client file."
        )
    if str(info.get("client_id", "")) != profile.oauth_client_id:
        raise AuthRequired("OAuth client ID does not match this profile.")
    if not info.get("refresh_token"):
        raise AuthRequired("Stored credential has no refresh token.")
    stored_scopes = normalize_scope_values(info.get("scopes"))
    if not set(REQUIRED_SCOPES).issubset(stored_scopes):
        raise AuthRequired(
            "Stored OAuth grant lacks the profile's required scopes."
        )

    dependencies = google_dependencies()
    credentials_info = dict(info)
    credentials_info.pop("_migration_binding", None)
    try:
        credentials = dependencies["Credentials"].from_authorized_user_info(
            credentials_info, scopes=REQUIRED_SCOPES
        )
    except Exception as exc:
        raise AuthRequired("Stored OAuth credential cannot be loaded.") from exc
    try:
        if not credentials.valid:
            credentials.refresh(dependencies["GoogleAuthRequest"]())
    except Exception as exc:
        lowered = str(exc).lower()
        if any(marker in lowered for marker in REAUTHORIZATION_MARKERS):
            raise AuthRequired(
                "Google rejected the refresh token (revoked, expired, password/admin "
                "policy changed, or OAuth app still in Testing)."
            ) from exc
        raise MigrationError(
            "Temporary OAuth refresh failure; the stored grant was preserved and should be retried."
        ) from exc
    granted_after_refresh = normalize_scope_values(
        getattr(credentials, "granted_scopes", None)
    )
    if granted_after_refresh and not set(REQUIRED_SCOPES).issubset(
        granted_after_refresh
    ):
        raise AuthRequired(
            "Google reports that the stored grant no longer has all required scopes."
        )
    service = build_gmail_service(credentials, dependencies)
    verify_exact_account(service, profile.destination)
    save_token_json(profile, credentials.to_json())
    return credentials, service, dependencies


def execute_idempotent(factory: Callable[[], Any], attempts: int = 5) -> Any:
    last_error: Exception | None = None
    for attempt in range(attempts):
        try:
            return factory().execute(num_retries=0)
        except Exception as exc:
            last_error = exc
            status_code, reasons, _ = http_error_details(exc)
            retryable = (
                status_code in {429, 500, 502, 503, 504}
                or bool(set(reasons) & TRANSIENT_REASONS)
                or (status_code == 0 and isinstance(exc, (OSError, TimeoutError)))
            )
            if not retryable or attempt + 1 == attempts:
                raise
            time.sleep(min(30.0, (2**attempt) + random.random()))
    assert last_error is not None
    raise last_error


def list_gmail_labels(service: Any) -> dict[str, str]:
    existing: dict[str, str] = {}
    try:
        response = execute_idempotent(
            lambda: service.users().labels().list(userId="me")
        )
    except Exception as exc:
        raise_if_google_access_block(exc, "listing Gmail labels")
        raise MigrationError(
            "Temporarily unable to list Gmail labels; authorization was preserved."
        ) from exc
    for label in response.get("labels", []):
        name = str(label.get("name", ""))
        label_id = str(label.get("id", ""))
        if name and label_id:
            existing[name] = label_id
    return existing


def ensure_gmail_labels(
    profile: Profile,
    manifest: dict[str, Any],
    checkpoint: dict[str, Any],
    service: Any,
) -> dict[str, str]:
    required_names = sorted(
        {
            name
            for row in manifest["messages"]
            for name in row.get("target_label_names", [])
        }
    )
    existing = list_gmail_labels(service)

    resolved: dict[str, str] = {}
    for name in required_names:
        label_id = existing.get(name)
        if not label_id:
            try:
                # Label creation is not idempotent. Do not ask the client to
                # retry a lost response; reconcile by listing labels instead.
                created = service.users().labels().create(
                    userId="me",
                    body={
                        "name": name,
                        "labelListVisibility": "labelShow",
                        "messageListVisibility": "show",
                    },
                ).execute(num_retries=0)
            except Exception as exc:
                raise_if_google_access_block(exc, f"creating Gmail label {name!r}")
                created = {}
            label_id = str(created.get("id", ""))
            if not label_id:
                label_id = list_gmail_labels(service).get(name, "")
            if not label_id:
                raise RunBlocked(
                    f"Gmail label creation for {name!r} was not confirmed; no message import began."
                )
        resolved[name] = label_id
    checkpoint["gmail_labels"] = resolved
    checkpoint["gmail_labels_verified_at"] = utc_now()
    save_checkpoint(profile, checkpoint)
    return resolved


def http_error_details(exc: Exception) -> tuple[int, list[str], str]:
    status_code = int(getattr(getattr(exc, "resp", None), "status", 0) or 0)
    message = ""
    reasons: list[str] = []
    content = getattr(exc, "content", b"")
    if isinstance(content, bytes):
        text = content.decode("utf-8", errors="replace")
    else:
        text = str(content or "")
    try:
        payload = json.loads(text) if text else {}
    except json.JSONDecodeError:
        payload = {}
    error = payload.get("error", {}) if isinstance(payload, dict) else {}
    if isinstance(error, dict):
        message = str(error.get("message", ""))
        entries = error.get("errors", [])
        if isinstance(entries, list):
            reasons = [
                str(item.get("reason", ""))
                for item in entries
                if isinstance(item, dict) and item.get("reason")
            ]
    if not message and hasattr(exc, "_get_reason"):
        try:
            message = str(exc._get_reason())
        except Exception:
            message = ""
    if not message:
        message = str(exc)
    return status_code, reasons, message[:1000]


def raise_if_google_access_block(exc: Exception, context: str) -> None:
    """Translate auth/policy failures without converting transient API errors."""
    status_code, reasons, message = http_error_details(exc)
    reason_set = set(reasons)
    refresh_grant_rejected = status_code == 0 and any(
        marker in message.lower() for marker in REAUTHORIZATION_MARKERS
    )
    if (
        status_code == 401
        or bool(reason_set & AUTH_ERROR_REASONS)
        or refresh_grant_rejected
    ):
        raise AuthRequired(
            f"Google rejected authorization while {context}; the checkpoint is safe."
        ) from exc
    if status_code == 403 and not bool(reason_set & TRANSIENT_REASONS):
        raise RunBlocked(
            f"Google policy or quota blocked {context}; authorization and the checkpoint "
            f"were preserved (reasons={reasons or ['unspecified_403']})."
        ) from exc


def classify_import_error(exc: Exception) -> str:
    status_code, reasons, message = http_error_details(exc)
    lowered = message.lower()
    if status_code == 400 and all(text in lowered for text in KNOWN_GMAIL_SECURITY_TEXT):
        return "known_google_security_rejection"
    if (
        status_code == 401
        or bool(set(reasons) & AUTH_ERROR_REASONS)
        or (
            status_code == 0
            and any(marker in lowered for marker in REAUTHORIZATION_MARKERS)
        )
    ):
        return "auth_required"
    if status_code in TRANSIENT_HTTP_STATUSES or set(reasons) & TRANSIENT_REASONS:
        return "uncertain"
    if status_code == 403 or bool(set(reasons) & POLICY_OR_QUOTA_REASONS):
        return "policy_or_quota_block"
    if status_code in {400, 413}:
        return "google_rejected"
    if status_code:
        return "google_rejected"
    return "uncertain"


def source_bytes_for_state(
    profile: Profile, row: dict[str, Any], state: dict[str, Any]
) -> tuple[bytes, dict[str, Any]]:
    replacement = state.get("replacement")
    if replacement is not None:
        if not isinstance(replacement, dict):
            raise MigrationError("Checkpoint replacement evidence is invalid.")
        path = Path(str(replacement.get("path", ""))).expanduser().resolve()
        replacements_root = (profile.state_dir / "replacements").resolve()
        if not is_within(path, replacements_root) or not path.is_file():
            raise MigrationError("Approved replacement is missing from state_dir/replacements.")
        prepared, observed = parse_source_path(path, replacements_root)
        expected = {
            "source_sha256": replacement.get("source_sha256"),
            "prepared_sha256": replacement.get("prepared_sha256"),
            "message_id": row["message_id"],
            "date_header": row["date_header"],
        }
        for field, value in expected.items():
            if observed.get(field) != value:
                raise MigrationError(f"Approved replacement field {field} changed.")
        return prepared, observed

    path = (profile.source_root / row["relative_path"]).resolve()
    if not is_within(path, profile.source_root):
        raise MigrationError("Source path escapes the preserved source root.")
    prepared, observed = parse_source_path(
        path, profile.source_root, profile.missing_message_id_policy
    )
    for field in (
        "source_sha256",
        "prepared_sha256",
        "repairs",
        "repair_occurrences",
        "source_parser_defects",
        "message_id",
        "message_id_provenance",
        "date_header",
    ):
        if observed.get(field) != row.get(field):
            raise MigrationError(
                f"Source changed immediately before import: {row['relative_path']} ({field})."
            )
    return prepared, observed


def gmail_query_for_message_id(message_id: str) -> str:
    return f"in:anywhere rfc822msgid:{message_id}"


def search_gmail_ids(service: Any, message_id: str) -> list[str]:
    found: list[str] = []
    page_token: str | None = None
    while True:
        try:
            response = execute_idempotent(
                lambda page_token=page_token: service.users().messages().list(
                    userId="me",
                    q=gmail_query_for_message_id(message_id),
                    includeSpamTrash=True,
                    maxResults=500,
                    pageToken=page_token,
                    fields="messages/id,nextPageToken",
                )
            )
        except Exception as exc:
            raise_if_google_access_block(exc, "searching Gmail for a Message-ID")
            raise MigrationError(
                "Temporarily unable to search Gmail; the checkpoint was preserved."
            ) from exc
        for item in response.get("messages", []):
            gmail_id = str(item.get("id", ""))
            if gmail_id:
                found.append(gmail_id)
        page_token = response.get("nextPageToken")
        if not page_token:
            break
    return sorted(set(found))


def known_gmail_ids_for_message_id(
    checkpoint: dict[str, Any], message_id: str, excluding_item: str
) -> set[str]:
    return {
        str(state.get("gmail_message_id"))
        for item_key, state in checkpoint["states"].items()
        if item_key != excluding_item
        and state.get("message_id") == message_id
        and state.get("gmail_message_id")
        and state.get("status")
        in {"verified", "verified_manual", "preexisting_reviewed"}
    }


def readback_message(service: Any, gmail_id: str) -> dict[str, Any]:
    try:
        return execute_idempotent(
            lambda: service.users().messages().get(
                userId="me",
                id=gmail_id,
                format="metadata",
                metadataHeaders=["Message-ID", "Date", "From", "To", "Cc", "Subject"],
                fields="id,threadId,labelIds,internalDate,payload/headers",
            )
        )
    except Exception as exc:
        raise_if_google_access_block(exc, f"reading back Gmail message {gmail_id}")
        status_code, _, _ = http_error_details(exc)
        if status_code == 404:
            raise
        raise MigrationError(
            "Temporarily unable to read back Gmail metadata; the checkpoint was preserved."
        ) from exc


def header_value(payload: dict[str, Any], name: str) -> str:
    headers = payload.get("payload", {}).get("headers", [])
    for header in headers:
        if str(header.get("name", "")).casefold() == name.casefold():
            return str(header.get("value", "")).strip()
    return ""


def header_semantic_date_ms(value: str) -> int | None:
    if not value:
        return None
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if parsed.tzinfo is None:
        if value.endswith("-0000"):
            parsed = parsed.replace(tzinfo=timezone.utc)
        else:
            return None
    return int(parsed.timestamp() * 1000)


def normalized_header_text(value: str) -> str:
    return " ".join(value.split())


def normalized_address_header(value: str) -> tuple[str, ...] | None:
    """Compare address headers semantically while preserving order.

    Gmail can quote a non-ASCII display name or add a conventional display name
    such as ``Mail Delivery System`` for a bare MAILER-DAEMON address.  The
    mailbox sequence is the stable delivery identity; display-name rendering is
    presentation-only.  Fall back to a mismatch when a nonempty value cannot be
    represented as actual mailbox addresses.
    """
    if not value.strip():
        return ()
    parsed = getaddresses([value])
    if not parsed or any(not address.strip() for _, address in parsed):
        return None
    # Gmail may collapse an identical recipient repeated in To/Cc. Preserve
    # order while treating exact duplicate mailbox entries as one semantic
    # delivery target.
    return tuple(
        dict.fromkeys(address.strip().casefold() for _, address in parsed)
    )


def verify_readback_payload(
    row: dict[str, Any],
    gmail_id: str,
    payload: dict[str, Any],
    expected_label_ids: Iterable[str],
) -> list[str]:
    issues: list[str] = []
    if str(payload.get("id", "")) != gmail_id:
        issues.append("readback Gmail ID differs from the accepted ID")
    if header_value(payload, "Message-ID") != row["message_id"]:
        issues.append("readback Message-ID differs from the source")
    returned_date = header_value(payload, "Date")
    if header_semantic_date_ms(returned_date) != int(row["expected_internal_date_ms"]):
        issues.append("readback Date header differs semantically from the source")
    for header_name, row_field in (
        ("From", "from"),
        ("To", "to"),
        ("Cc", "cc"),
    ):
        returned_value = header_value(payload, header_name)
        source_value = str(row.get(row_field, ""))
        returned_addresses = normalized_address_header(returned_value)
        source_addresses = normalized_address_header(source_value)
        if returned_addresses is not None and source_addresses is not None:
            values_match = returned_addresses == source_addresses
        else:
            values_match = normalized_header_text(
                returned_value
            ) == normalized_header_text(source_value)
        if not values_match:
            issues.append(f"readback {header_name} header differs from the source")
    if normalized_header_text(header_value(payload, "Subject")) != normalized_header_text(
        str(row.get("subject", ""))
    ):
        issues.append("readback Subject header differs from the source")
    returned_internal_date = str(payload.get("internalDate", ""))
    if returned_internal_date != str(row["expected_internal_date_ms"]):
        issues.append("readback internalDate differs from the source Date")
    returned_labels = {str(item) for item in payload.get("labelIds", [])}
    missing_labels = sorted(set(expected_label_ids) - returned_labels)
    if missing_labels:
        issues.append(f"readback is missing expected labels: {missing_labels}")
    return issues


def expected_label_ids_for_row(
    row: dict[str, Any], label_map: dict[str, str]
) -> list[str]:
    custom = [label_map[name] for name in row.get("target_label_names", [])]
    system = [str(item) for item in row.get("target_system_label_ids", [])]
    return list(dict.fromkeys(custom + system))


def checkpoint_gmail_ids(checkpoint: dict[str, Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    for item_key, state in checkpoint["states"].items():
        gmail_id = str(state.get("gmail_message_id", ""))
        if gmail_id:
            result[gmail_id] = item_key
    return result


def mark_verified_from_payload(
    profile: Profile,
    checkpoint: dict[str, Any],
    row: dict[str, Any],
    gmail_id: str,
    payload: dict[str, Any],
    expected_label_ids: list[str],
    reconciled: bool = False,
) -> bool:
    item_key = row["item_key"]
    state = checkpoint["states"][item_key]
    issues = verify_readback_payload(row, gmail_id, payload, expected_label_ids)
    if issues:
        save_state(
            profile,
            checkpoint,
            item_key,
            status="review_required",
            gmail_message_id=gmail_id,
            gmail_thread_id=str(payload.get("threadId", "")),
            returned_label_ids=payload.get("labelIds", []),
            returned_internal_date=str(payload.get("internalDate", "")),
            readback_issues=issues,
            readback_at=utc_now(),
        )
        return False
    owner = checkpoint_gmail_ids(checkpoint).get(gmail_id)
    if owner is not None and owner != item_key:
        raise MigrationError(f"Gmail ID {gmail_id} is already assigned to another source row.")
    save_state(
        profile,
        checkpoint,
        item_key,
        status="verified",
        gmail_message_id=gmail_id,
        gmail_thread_id=str(payload.get("threadId", "")),
        returned_label_ids=payload.get("labelIds", []),
        returned_internal_date=str(payload.get("internalDate", "")),
        verified_at=utc_now(),
        verified_prepared_sha256=(
            state.get("uploaded_prepared_sha256")
            or state.get("attempted_prepared_sha256")
            or ""
        ),
        reconciled_after_uncertain=bool(reconciled),
        readback_issues=[],
        final_reconciliation_failure=None,
    )
    return True


def reconcile_uncertain(
    profile: Profile,
    checkpoint: dict[str, Any],
    row: dict[str, Any],
    service: Any,
    expected_label_ids: list[str],
    delays: Iterable[float] = DEFAULT_RECONCILIATION_DELAYS,
) -> bool:
    item_key = row["item_key"]
    known_ids = known_gmail_ids_for_message_id(
        checkpoint, row["message_id"], excluding_item=item_key
    )
    ignored_preexisting = {
        str(item)
        for item in checkpoint["states"][item_key].get(
            "ignored_preexisting_gmail_ids", []
        )
    }
    prior_observations = checkpoint["states"][item_key].get(
        "reconciliation_observations", []
    )
    if not isinstance(prior_observations, list):
        raise MigrationError("Checkpoint reconciliation observations are invalid.")
    observations: list[dict[str, Any]] = list(prior_observations)
    for delay in delays:
        if delay:
            time.sleep(delay)
        matches = search_gmail_ids(service, row["message_id"])
        unknown = sorted(set(matches) - known_ids - ignored_preexisting)
        observations.append(
            {"checked_at": utc_now(), "match_ids": matches, "new_candidate_ids": unknown}
        )
        if len(unknown) == 1:
            payload = readback_message(service, unknown[0])
            if mark_verified_from_payload(
                profile,
                checkpoint,
                row,
                unknown[0],
                payload,
                expected_label_ids,
                reconciled=True,
            ):
                checkpoint["states"][item_key]["reconciliation_observations"] = observations
                save_checkpoint(profile, checkpoint)
                return True
            checkpoint["states"][item_key]["reconciliation_observations"] = observations
            save_checkpoint(profile, checkpoint)
            return False
        if len(unknown) > 1:
            save_state(
                profile,
                checkpoint,
                item_key,
                status="review_required",
                reconciliation_observations=observations,
                readback_issues=["multiple new Gmail candidates after an ambiguous import"],
            )
            return False
    save_state(
        profile,
        checkpoint,
        item_key,
        status="uncertain",
        reconciliation_observations=observations,
        error=(
            "No new Gmail candidate was found after an ambiguous request. A zero search "
            "result is not proof that Gmail did not accept the message."
        ),
    )
    return False


def import_one(
    profile: Profile,
    checkpoint: dict[str, Any],
    row: dict[str, Any],
    service: Any,
    dependencies: dict[str, Any],
    label_map: dict[str, str],
    continue_known_security_rejections: bool = False,
) -> str:
    item_key = row["item_key"]
    state = checkpoint["states"][item_key]
    expected_label_ids = expected_label_ids_for_row(row, label_map)

    known_ids = known_gmail_ids_for_message_id(
        checkpoint, row["message_id"], excluding_item=item_key
    )
    matches = search_gmail_ids(service, row["message_id"])
    ignored_preexisting = {
        str(item) for item in state.get("ignored_preexisting_gmail_ids", [])
    }
    unknown_preexisting = sorted(set(matches) - known_ids - ignored_preexisting)
    if unknown_preexisting:
        save_state(
            profile,
            checkpoint,
            item_key,
            status="preexisting_conflict",
            preexisting_gmail_ids=unknown_preexisting,
            baseline_checked_at=utc_now(),
            error="Destination already contains an unowned matching Message-ID.",
        )
        return "blocked"

    prepared, observed = source_bytes_for_state(profile, row, state)
    upload_protocol = select_gmail_upload_protocol(prepared)
    save_state(
        profile,
        checkpoint,
        item_key,
        status="inflight",
        attempted_at=utc_now(),
        attempted_prepared_sha256=sha256_bytes(prepared),
        baseline_checked_at=utc_now(),
        baseline_unknown_gmail_ids=[],
        baseline_ignored_gmail_ids=sorted(ignored_preexisting),
        last_attempted_upload_protocol=upload_protocol,
        last_attempted_upload_size_bytes=len(prepared),
    )
    try:
        media_kwargs: dict[str, Any] = {
            "mimetype": "message/rfc822",
            "resumable": upload_protocol == GMAIL_UPLOAD_PROTOCOL_RESUMABLE,
        }
        if upload_protocol == GMAIL_UPLOAD_PROTOCOL_RESUMABLE:
            media_kwargs["chunksize"] = 5 * 1024 * 1024
        media = dependencies["MediaIoBaseUpload"](
            io.BytesIO(prepared), **media_kwargs
        )
        request = service.users().messages().import_(
            userId="me",
            body={"labelIds": expected_label_ids},
            media_body=media,
            internalDateSource="dateHeader",
            neverMarkSpam=True,
            processForCalendar=False,
            deleted=False,
            fields="id,threadId,labelIds,internalDate",
        )
    except Exception as exc:
        save_state(
            profile,
            checkpoint,
            item_key,
            status="pending",
            local_request_construction_error_type=type(exc).__name__,
            local_request_construction_error_at=utc_now(),
            local_request_construction_error=(
                "Gmail import request construction failed locally before execute()."
            ),
        )
        raise MigrationError(
            "Gmail import request construction failed locally before any write."
        ) from exc
    try:
        result = request.execute(num_retries=0)
    except KeyboardInterrupt:
        save_state(
            profile,
            checkpoint,
            item_key,
            status="uncertain",
            error_type="KeyboardInterrupt",
            error="Interrupted after the Gmail import request began.",
        )
        return "blocked"
    except Exception as exc:
        status_code, reasons, message = http_error_details(exc)
        classification = classify_import_error(exc)
        error_fingerprint = sha256_bytes(
            canonical_json_bytes(
                {"http_status": status_code, "reasons": reasons, "message": message}
            )
        )
        if classification == "known_google_security_rejection":
            if (
                profile.rejection_policy
                == "local_only_known_security_and_continue"
                or continue_known_security_rejections
            ):
                save_state(
                    profile,
                    checkpoint,
                    item_key,
                    status="local_only_reviewed",
                    decision=(
                        "run_confirmed_known_google_security_policy"
                        if continue_known_security_rejections
                        else "profile_known_google_security_policy"
                    ),
                    decision_reason=(
                        "Gmail returned the exact allowlisted Invalid attachment rejection; "
                        "the run was explicitly confirmed to preserve the source locally and continue."
                    ),
                    decided_at=utc_now(),
                    http_status=status_code,
                    google_error_reasons=reasons,
                    google_error=message,
                    google_error_fingerprint=error_fingerprint,
                    gmail_message_id="",
                    source_preserved=True,
                )
                return "local_only"
            save_state(
                profile,
                checkpoint,
                item_key,
                status="google_rejected",
                rejection_kind="known_google_security_rejection",
                http_status=status_code,
                google_error_reasons=reasons,
                google_error=message,
                google_error_fingerprint=error_fingerprint,
                gmail_message_id="",
                source_preserved=True,
            )
            return "blocked"
        if classification == "uncertain":
            save_state(
                profile,
                checkpoint,
                item_key,
                status="uncertain",
                http_status=status_code,
                google_error_reasons=reasons,
                google_error=message,
                google_error_fingerprint=error_fingerprint,
            )
            return (
                "verified"
                if reconcile_uncertain(
                    profile,
                    checkpoint,
                    row,
                    service,
                    expected_label_ids,
                )
                else "blocked"
            )
        if classification == "auth_required":
            save_state(
                profile,
                checkpoint,
                item_key,
                status="pending",
                last_auth_error_at=utc_now(),
                last_http_status=status_code,
                last_google_error_reasons=reasons,
                last_google_error=message,
                last_google_error_fingerprint=error_fingerprint,
            )
            raise AuthRequired(
                "Gmail rejected the import authorization; the checkpoint is safe."
            )
        if classification == "policy_or_quota_block":
            save_state(
                profile,
                checkpoint,
                item_key,
                status="pending",
                last_policy_or_quota_error_at=utc_now(),
                last_http_status=status_code,
                last_google_error_reasons=reasons,
                last_google_error=message,
                last_google_error_fingerprint=error_fingerprint,
            )
            raise RunBlocked(
                "Google policy or quota blocked the import; authorization was preserved. "
                "Fix the reported Google-side cause, then run the same command to resume."
            )
        save_state(
            profile,
            checkpoint,
            item_key,
            status="google_rejected",
            rejection_kind=classification,
            http_status=status_code,
            google_error_reasons=reasons,
            google_error=message,
            google_error_fingerprint=error_fingerprint,
            gmail_message_id="",
            source_preserved=True,
        )
        return "blocked"

    gmail_id = str(result.get("id", ""))
    if not gmail_id:
        save_state(
            profile,
            checkpoint,
            item_key,
            status="uncertain",
            error="Gmail returned a success response without a message ID.",
        )
        return "blocked"
    if gmail_id in ignored_preexisting:
        save_state(
            profile,
            checkpoint,
            item_key,
            status="review_required",
            gmail_message_id="",
            conflicting_gmail_message_id=gmail_id,
            readback_issues=[
                "Gmail returned an explicitly ignored preexisting ID instead of a new import ID"
            ],
        )
        return "blocked"
    owner = checkpoint_gmail_ids(checkpoint).get(gmail_id)
    if owner is not None and owner != item_key:
        save_state(
            profile,
            checkpoint,
            item_key,
            status="review_required",
            gmail_message_id="",
            conflicting_gmail_message_id=gmail_id,
            conflicting_owner_item_key=owner,
            readback_issues=["returned Gmail ID already belongs to another source row"],
        )
        return "blocked"
    save_state(
        profile,
        checkpoint,
        item_key,
        status="imported_pending_verification",
        imported_at=utc_now(),
        gmail_message_id=gmail_id,
        gmail_thread_id=str(result.get("threadId", "")),
        response_label_ids=result.get("labelIds", []),
        response_internal_date=str(result.get("internalDate", "")),
        uploaded_prepared_sha256=observed["prepared_sha256"],
    )
    try:
        payload = readback_message(service, gmail_id)
    except MigrationError:
        # The import ID is already durable in imported_pending_verification.
        # Auth, policy, quota, and transient control-plane failures must not be
        # mislabeled as a message-content mismatch.
        raise
    except Exception as exc:
        save_state(
            profile,
            checkpoint,
            item_key,
            status="review_required",
            error_type=type(exc).__name__,
            readback_issues=["Gmail accepted the import but metadata readback failed"],
        )
        return "blocked"
    return (
        "verified"
        if mark_verified_from_payload(
            profile,
            checkpoint,
            row,
            gmail_id,
            payload,
            expected_label_ids,
        )
        else "blocked"
    )


def row_by_key(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {row["item_key"]: row for row in manifest["messages"]}


def verify_preexisting_candidate(
    profile: Profile,
    checkpoint: dict[str, Any],
    row: dict[str, Any],
    service: Any,
) -> bool:
    item_key = row["item_key"]
    state = checkpoint["states"][item_key]
    gmail_id = str(state.get("gmail_message_id", ""))
    if not gmail_id:
        raise MigrationError("Preexisting candidate has no Gmail ID.")
    try:
        payload = readback_message(service, gmail_id)
    except MigrationError:
        raise
    except Exception as exc:
        status_code, _, _ = http_error_details(exc)
        if status_code != 404:
            raise
        save_state(
            profile,
            checkpoint,
            item_key,
            status="review_required",
            review_origin="preexisting_candidate",
            readback_issues=["selected preexisting Gmail candidate no longer exists"],
            readback_at=utc_now(),
        )
        return False
    issues = verify_readback_payload(row, gmail_id, payload, [])
    if issues:
        save_state(
            profile,
            checkpoint,
            item_key,
            status="review_required",
            review_origin="preexisting_candidate",
            readback_issues=issues,
            readback_at=utc_now(),
        )
        return False
    save_state(
        profile,
        checkpoint,
        item_key,
        status="preexisting_reviewed",
        gmail_message_id=gmail_id,
        gmail_thread_id=str(payload.get("threadId", "")),
        returned_label_ids=payload.get("labelIds", []),
        returned_internal_date=str(payload.get("internalDate", "")),
        verified_at=utc_now(),
        readback_issues=[],
    )
    return True


def recover_or_verify_existing_state(
    profile: Profile,
    checkpoint: dict[str, Any],
    row: dict[str, Any],
    service: Any,
    label_map: dict[str, str],
) -> bool:
    item_key = row["item_key"]
    state = checkpoint["states"][item_key]
    status_value = state["status"]
    expected_label_ids = expected_label_ids_for_row(row, label_map)
    if status_value in {"inflight", "uncertain"}:
        if status_value == "inflight":
            save_state(
                profile,
                checkpoint,
                item_key,
                status="uncertain",
                error="A previous process ended while this Gmail request was inflight.",
            )
        return reconcile_uncertain(
            profile, checkpoint, row, service, expected_label_ids
        )
    if (
        status_value == "review_required"
        and state.get("review_origin") == "preexisting_candidate"
        and state.get("gmail_message_id")
    ):
        return verify_preexisting_candidate(profile, checkpoint, row, service)
    if status_value in {"imported_pending_verification", "review_required"} and state.get(
        "gmail_message_id"
    ):
        try:
            payload = readback_message(service, str(state["gmail_message_id"]))
        except MigrationError:
            raise
        except Exception as exc:
            status_code, _, _ = http_error_details(exc)
            if status_code != 404:
                raise
            save_state(
                profile,
                checkpoint,
                item_key,
                status="review_required",
                readback_issues=["accepted Gmail import ID no longer exists"],
                readback_at=utc_now(),
            )
            return False
        return mark_verified_from_payload(
            profile,
            checkpoint,
            row,
            str(state["gmail_message_id"]),
            payload,
            expected_label_ids,
        )
    if status_value == "candidate_pending_verification" and state.get(
        "gmail_message_id"
    ):
        try:
            payload = readback_message(service, str(state["gmail_message_id"]))
        except MigrationError:
            raise
        except Exception as exc:
            status_code, _, _ = http_error_details(exc)
            if status_code != 404:
                raise
            save_state(
                profile,
                checkpoint,
                item_key,
                status="review_required",
                readback_issues=["selected reconciliation candidate no longer exists"],
                readback_at=utc_now(),
            )
            return False
        return mark_verified_from_payload(
            profile,
            checkpoint,
            row,
            str(state["gmail_message_id"]),
            payload,
            expected_label_ids,
            reconciled=True,
        )
    if status_value == "preexisting_pending_verification":
        return verify_preexisting_candidate(
            profile, checkpoint, row, service
        )
    return False


def resolve_exact_duplicate_source_row(
    profile: Profile,
    manifest: dict[str, Any],
    checkpoint: dict[str, Any],
    row: dict[str, Any],
    label_map: dict[str, str],
) -> bool:
    """Represent an exact exported copy by its one verified canonical Gmail item."""
    item_key = row["item_key"]
    canonical_key = str(row.get("represented_by_item_key", ""))
    rows = row_by_key(manifest)
    canonical_row = rows.get(canonical_key)
    canonical_state = checkpoint["states"].get(canonical_key)
    if canonical_row is None or canonical_state is None:
        raise MigrationError("Exact duplicate has no canonical row in the active migration.")

    expected_labels = set(expected_label_ids_for_row(canonical_row, label_map))
    returned_labels = {
        str(value) for value in canonical_state.get("returned_label_ids", [])
    }
    safe = (
        canonical_state.get("status") == "verified"
        and bool(canonical_state.get("gmail_message_id"))
        and canonical_state.get("verified_prepared_sha256")
        == row.get("prepared_sha256")
        and canonical_state.get("readback_issues") == []
        and expected_labels.issubset(returned_labels)
        and not canonical_state.get("final_reconciliation_failure")
    )
    if (
        canonical_state.get("status") == "local_only_reviewed"
        and canonical_state.get("source_preserved") is True
        and canonical_state.get("attempted_prepared_sha256")
        == row.get("prepared_sha256")
    ):
        save_state(
            profile,
            checkpoint,
            item_key,
            status="duplicate_local_only_reviewed",
            represented_by_item_key=canonical_key,
            represented_prepared_sha256=str(row["prepared_sha256"]),
            verified_at=utc_now(),
            decision="inherit_exact_canonical_local_only_outcome",
            decision_reason=(
                "Prepared bytes are identical to a canonical upload that has a reviewed, "
                "source-preserved local-only outcome."
            ),
            source_preserved=True,
        )
        return True
    if not safe:
        save_state(
            profile,
            checkpoint,
            item_key,
            status="duplicate_pending_canonical",
            error=(
                "The exact-copy canonical row is not a matching, fully label-verified Gmail "
                "import. Preexisting, manual, replacement-mismatch, rejected, and unresolved "
                "canonical outcomes cannot automatically represent this source row."
            ),
        )
        return False

    save_state(
        profile,
        checkpoint,
        item_key,
        status="duplicate_source_reviewed",
        represented_by_item_key=canonical_key,
        represented_by_gmail_id=str(canonical_state["gmail_message_id"]),
        represented_prepared_sha256=str(row["prepared_sha256"]),
        canonical_union_label_ids=sorted(expected_labels),
        verified_at=utc_now(),
        decision="merge_exact_prepared_copy_into_canonical_gmail_message",
        decision_reason=(
            "Prepared bytes are identical; the canonical Gmail message was read back with "
            "the union of all source-folder labels."
        ),
        source_preserved=True,
        final_reconciliation_failure=None,
    )
    return True


def final_reconcile_terminal_gmail(
    profile: Profile,
    manifest: dict[str, Any],
    checkpoint: dict[str, Any],
    service: Any,
    label_map: dict[str, str],
) -> bool:
    """Re-read every Gmail-covered terminal row before declaring completion."""
    all_verified = True
    processed = 0
    for row in manifest["messages"]:
        item_key = row["item_key"]
        state = checkpoint["states"][item_key]
        status_value = state["status"]
        if status_value not in {"verified", "verified_manual", "preexisting_reviewed"}:
            continue
        processed += 1
        gmail_id = str(state.get("gmail_message_id", ""))
        if not gmail_id:
            state["final_reconciliation_failure"] = {
                "checked_at": utc_now(),
                "issues": ["terminal Gmail-covered row has no Gmail ID"],
            }
            state.pop("final_readback_verified_at", None)
            save_checkpoint(profile, checkpoint)
            all_verified = False
            continue
        try:
            payload = readback_message(service, gmail_id)
        except (AuthRequired, RunBlocked) as exc:
            checkpoint["final_reconciliation"] = {
                "checked_at": utc_now(),
                "status": "blocked",
                "blocked_item_key": item_key,
                "error_type": type(exc).__name__,
            }
            save_checkpoint(profile, checkpoint)
            raise
        except MigrationError as exc:
            checkpoint["final_reconciliation"] = {
                "checked_at": utc_now(),
                "status": "blocked",
                "blocked_item_key": item_key,
                "error_type": type(exc).__name__,
            }
            save_checkpoint(profile, checkpoint)
            raise
        except Exception as exc:
            status_code, reasons, _ = http_error_details(exc)
            state["final_reconciliation_failure"] = {
                "checked_at": utc_now(),
                "issues": ["final Gmail readback request failed"],
                "error_type": type(exc).__name__,
                "http_status": status_code,
                "google_error_reasons": reasons,
            }
            state.pop("final_readback_verified_at", None)
            checkpoint["final_reconciliation"] = {
                "checked_at": utc_now(),
                "status": "blocked",
                "blocked_item_key": item_key,
            }
            save_checkpoint(profile, checkpoint)
            all_verified = False
            if status_code == 401 or bool(set(reasons) & AUTH_ERROR_REASONS):
                raise AuthRequired(
                    "Google rejected authorization during final readback; the checkpoint is safe."
                ) from exc
            if status_code == 403:
                raise RunBlocked(
                    "Google policy or quota blocked final readback; authorization and the "
                    "checkpoint were preserved."
                ) from exc
            if status_code != 404:
                return False
            continue

        if status_value == "verified":
            issues = verify_readback_payload(
                row,
                gmail_id,
                payload,
                expected_label_ids_for_row(row, label_map),
            )
        elif status_value == "preexisting_reviewed":
            issues = verify_readback_payload(row, gmail_id, payload, [])
        else:
            issues = []
            if str(payload.get("id", "")) != gmail_id:
                issues.append("final readback Gmail ID differs from the reviewed ID")
            if header_value(payload, "Message-ID") != row["message_id"]:
                issues.append("final readback Message-ID differs from the source")
        if issues:
            state["final_reconciliation_failure"] = {
                "checked_at": utc_now(),
                "issues": issues,
            }
            state.pop("final_readback_verified_at", None)
            save_checkpoint(profile, checkpoint)
            all_verified = False
        else:
            state.pop("final_reconciliation_failure", None)
            state["final_readback_verified_at"] = utc_now()
            state["final_readback_label_ids"] = payload.get("labelIds", [])
            if processed % profile.progress_every == 0:
                save_checkpoint(profile, checkpoint)

    # Exact exported copies do not own a second Gmail ID.  Reconfirm that each
    # still depends on a currently verified canonical import whose latest
    # readback contains the frozen union label set.
    for row in manifest["messages"]:
        item_key = row["item_key"]
        state = checkpoint["states"][item_key]
        if state["status"] != "duplicate_source_reviewed":
            continue
        canonical = checkpoint["states"].get(str(state.get("represented_by_item_key")))
        issues: list[str] = []
        if canonical is None or canonical.get("status") != "verified":
            issues.append("canonical row is no longer a verified Gmail import")
        else:
            if state.get("represented_by_gmail_id") != canonical.get("gmail_message_id"):
                issues.append("canonical Gmail ID changed")
            if canonical.get("verified_prepared_sha256") != row.get("prepared_sha256"):
                issues.append("canonical verified upload hash differs from the exact copy")
            if canonical.get("final_reconciliation_failure"):
                issues.append("canonical final readback failed")
            latest_labels = {
                str(value) for value in canonical.get("final_readback_label_ids", [])
            }
            expected_labels = {
                str(value) for value in state.get("canonical_union_label_ids", [])
            }
            if not expected_labels.issubset(latest_labels):
                issues.append("canonical final readback lacks a union folder label")
        if issues:
            state["final_reconciliation_failure"] = {
                "checked_at": utc_now(),
                "issues": issues,
            }
            save_checkpoint(profile, checkpoint)
            all_verified = False
        else:
            state.pop("final_reconciliation_failure", None)
            state["final_readback_verified_at"] = utc_now()
    checkpoint["final_reconciliation"] = {
        "checked_at": utc_now(),
        "status": "verified" if all_verified else "blocked",
    }
    save_checkpoint(profile, checkpoint)
    return all_verified


def build_report(
    profile: Profile, manifest: dict[str, Any], checkpoint: dict[str, Any] | None
) -> dict[str, Any]:
    if checkpoint is None:
        counts = {"pending": len(manifest["messages"])}
        states: dict[str, Any] = {}
    else:
        states = checkpoint["states"]
        counts = dict(Counter(state["status"] for state in states.values()))
    total = len(manifest["messages"])
    if sum(counts.values()) != total:
        raise MigrationError("Checkpoint status counts do not equal the source denominator.")
    accounted = sum(counts.get(status_value, 0) for status_value in TERMINAL_STATUSES)
    blocking = sum(counts.get(status_value, 0) for status_value in BLOCKING_STATUSES)
    pending = total - accounted - blocking
    google_verified = counts.get("verified", 0) + counts.get("verified_manual", 0)
    preexisting_reviewed = counts.get("preexisting_reviewed", 0)
    duplicate_source_reviewed = counts.get("duplicate_source_reviewed", 0)
    gmail_covered = google_verified + preexisting_reviewed + duplicate_source_reviewed
    accounted_complete = accounted == total and blocking == 0 and pending == 0
    final_failures = [
        item_key
        for item_key, state in states.items()
        if state.get("final_reconciliation_failure")
    ]
    final_reconciliation_verified = bool(
        checkpoint
        and checkpoint.get("final_reconciliation", {}).get("status") == "verified"
    )
    unresolved_extra_candidate_rows = [
        item_key
        for item_key, state in states.items()
        if state.get("unselected_candidate_ids")
        and not state.get("unselected_candidates_reviewed")
    ]
    label_map = checkpoint.get("gmail_labels", {}) if checkpoint else {}
    folder_label_covered = 0
    manifest_rows = row_by_key(manifest)
    for item_key, state in states.items():
        row = manifest_rows[item_key]
        status_value = state.get("status")
        if state.get("final_reconciliation_failure"):
            continue
        if status_value == "duplicate_source_reviewed":
            folder_label_covered += 1
            continue
        if status_value not in {"verified", "verified_manual", "preexisting_reviewed"}:
            continue
        try:
            expected_labels = set(expected_label_ids_for_row(row, label_map))
        except KeyError:
            expected_labels = set()
        observed_labels = {
            str(value)
            for value in (
                state.get("final_readback_label_ids")
                or state.get("returned_label_ids")
                or []
            )
        }
        if expected_labels and expected_labels.issubset(observed_labels):
            folder_label_covered += 1

    gmail_presence_complete = (
        gmail_covered == total
        and accounted_complete
        and not final_failures
        and not unresolved_extra_candidate_rows
        and final_reconciliation_verified
    )
    folder_label_complete = (
        folder_label_covered == total
        and not final_failures
        and final_reconciliation_verified
    )
    gmail_complete = gmail_presence_complete and folder_label_complete
    gmail_covered_rows_folder_complete = folder_label_covered == gmail_covered
    transformed_by_item: dict[str, dict[str, Any]] = {}
    for row in manifest["messages"]:
        if not row.get("repairs"):
            continue
        item_key = str(row["item_key"])
        state = states.get(item_key, {})
        transformed_by_item[item_key] = {
            "item_key": item_key,
            "relative_path": row.get("relative_path"),
            "status": state.get("status", "pending"),
            "preparation_repairs": list(row.get("repairs", [])),
            "repair_occurrences": dict(row.get("repair_occurrences", {})),
            "source_parser_defects": list(
                row.get("source_parser_defects", [])
            ),
            "message_id_provenance": dict(
                row.get("message_id_provenance", {})
            ),
            "source_sha256": row.get("source_sha256"),
            "prepared_sha256": row.get("prepared_sha256"),
            "source_original_preserved": True,
        }
    for item_key, state in states.items():
        replacement = state.get("replacement")
        if not isinstance(replacement, dict):
            continue
        transformed_by_item.setdefault(
            item_key,
            {
                "item_key": item_key,
                "relative_path": state.get("relative_path"),
                "status": state.get("status"),
                "preparation_repairs": [],
                "repair_occurrences": {},
                "source_parser_defects": [],
                "message_id_provenance": {},
            },
        ).update(
            replacement_path=replacement.get("path"),
            replacement_prepared_sha256=replacement.get("prepared_sha256"),
            source_original_preserved=replacement.get(
                "source_original_preserved"
            ),
        )
    transformed = [transformed_by_item[key] for key in sorted(transformed_by_item)]
    upload_protocol_counts = dict(
        Counter(
            str(
                state.get(
                    "last_attempted_upload_protocol", "unrecorded_legacy"
                )
            )
            for state in states.values()
            if state.get("attempted_at")
        )
    )
    collision_item_keys = {
        str(item_key)
        for group in manifest.get("distinct_prepared_message_id_collisions", [])
        for item_key in group.get("member_item_keys", [])
    }
    exceptions = []
    for item_key, state in states.items():
        manifest_row = manifest_rows[item_key]
        history = state.get("review_history", [])
        material = (
            state.get("status")
            in {
                "local_only_reviewed",
                "duplicate_source_reviewed",
                "duplicate_local_only_reviewed",
                "google_rejected",
                "uncertain",
                "review_required",
                "preexisting_conflict",
                "preexisting_reviewed",
                "verified_manual",
            }
            or isinstance(state.get("replacement"), dict)
            or bool(history)
            or bool(state.get("ignored_preexisting_gmail_ids"))
            or bool(state.get("unselected_candidate_ids"))
            or bool(state.get("final_reconciliation_failure"))
            or bool(state.get("last_policy_or_quota_error_at"))
            or bool(manifest_row.get("repairs"))
            or item_key in collision_item_keys
        )
        if not material:
            continue
        exceptions.append(
            {
                "item_key": item_key,
                "relative_path": state.get("relative_path"),
                "status": state.get("status"),
                "decision": state.get("decision"),
                "decision_reason": state.get("decision_reason"),
                "reason": state.get("decision_reason")
                or state.get("google_error")
                or state.get("last_google_error")
                or state.get("error"),
                "review_history": history,
                "ignored_preexisting_gmail_ids": state.get(
                    "ignored_preexisting_gmail_ids", []
                ),
                "unselected_candidate_ids": state.get(
                    "unselected_candidate_ids", []
                ),
                "unselected_candidates_reviewed": state.get(
                    "unselected_candidates_reviewed"
                ),
                "final_reconciliation_failure": state.get(
                    "final_reconciliation_failure"
                ),
                "resolved_final_reconciliation_failure": state.get(
                    "resolved_final_reconciliation_failure"
                ),
                "previous_terminal_gmail_id": state.get(
                    "previous_terminal_gmail_id"
                ),
                "prior_terminal_gmail_evidence": state.get(
                    "prior_terminal_gmail_evidence", []
                ),
                "prior_duplicate_representation": state.get(
                    "prior_duplicate_representation", []
                ),
                "distinct_prepared_message_id_collision": (
                    item_key in collision_item_keys
                ),
                "preparation_repairs": list(manifest_row.get("repairs", [])),
                "repair_occurrences": dict(
                    manifest_row.get("repair_occurrences", {})
                ),
                "source_parser_defects": list(
                    manifest_row.get("source_parser_defects", [])
                ),
                "message_id_provenance": dict(
                    manifest_row.get("message_id_provenance", {})
                ),
            }
        )
    return {
        "schema_version": 2,
        "generated_at": utc_now(),
        "migration_id": profile.migration_id,
        "source_mailbox": profile.source_mailbox,
        "destination": profile.destination,
        "source_eml_denominator": total,
        "status_counts": counts,
        "accounted_for": accounted,
        "blocking": blocking,
        "pending_or_inflight": pending,
        "complete": accounted_complete,
        "accounted_complete": accounted_complete,
        "completion_basis": (
            "Every frozen source row has a terminal checkpoint outcome. See gmail_complete "
            "for the stricter Gmail-presence and folder-label result."
        ),
        "gmail_complete": gmail_complete,
        "gmail_message_presence_complete": gmail_presence_complete,
        "folder_label_complete": folder_label_complete,
        "gmail_covered_rows_folder_complete": gmail_covered_rows_folder_complete,
        "final_reconciliation_verified": final_reconciliation_verified,
        "final_reconciliation_failure_rows": final_failures,
        "unresolved_extra_candidate_rows": unresolved_extra_candidate_rows,
        "verification_scope": (
            "Gmail ID, selected headers, internalDate, and expected labels; raw body and "
            "attachment byte-equivalence is not asserted"
        ),
        "source_files_modified": 0,
        "google_verified": google_verified,
        "preexisting_reviewed": preexisting_reviewed,
        "gmail_covered_source_rows": gmail_covered,
        "folder_label_covered_source_rows": folder_label_covered,
        "unique_gmail_message_ids": len(
            {
                str(state.get("gmail_message_id"))
                for state in states.values()
                if state.get("gmail_message_id")
            }
        ),
        "unique_gmail_upload_rows": manifest.get("unique_gmail_upload_rows"),
        "local_only_reviewed": (
            counts.get("local_only_reviewed", 0)
            + counts.get("duplicate_local_only_reviewed", 0)
        ),
        "duplicate_source_reviewed": duplicate_source_reviewed,
        "temporary_repair_counts": manifest.get("temporary_repair_counts", {}),
        "temporary_repair_occurrence_counts": manifest.get(
            "temporary_repair_occurrence_counts", {}
        ),
        "generated_message_id_source_rows": manifest.get(
            "generated_message_id_source_rows", 0
        ),
        "current_upload_protocol": GMAIL_UPLOAD_STRATEGY,
        "source_rows_by_last_attempted_upload_protocol": upload_protocol_counts,
        "upload_protocol_note": (
            "unrecorded_legacy denotes source rows attempted before upload-protocol "
            "tracking was added; counts are source rows by their last attempt, not request counts."
        ),
        "transformed_upload_count": len(transformed),
        "transformed_uploads": transformed,
        "exceptions": exceptions,
    }


def print_report(report: dict[str, Any]) -> None:
    print("source_eml_denominator:", report["source_eml_denominator"])
    for status_value, count in sorted(report["status_counts"].items()):
        print(f"status_{status_value}:", count)
    print("accounted_for:", report["accounted_for"])
    print("blocking:", report["blocking"])
    print("pending_or_inflight:", report["pending_or_inflight"])
    print("accounted_complete:", str(report["accounted_complete"]).lower())
    print("gmail_complete:", str(report["gmail_complete"]).lower())
    print(
        "gmail_message_presence_complete:",
        str(report["gmail_message_presence_complete"]).lower(),
    )
    print("folder_label_complete:", str(report["folder_label_complete"]).lower())
    print("complete:", str(report["complete"]).lower())


def command_run(
    profile: Profile,
    confirm_destination: str | None,
    confirm_source_count: int | None,
    continue_known_security_rejections: bool = False,
) -> int:
    manifest = load_manifest(profile)
    if (confirm_destination or "").strip().lower() != profile.destination:
        raise MigrationError(
            f"Execution requires --confirm-destination {profile.destination}."
        )
    expected_count = int(manifest["source_eml_count"])
    if confirm_source_count != expected_count:
        raise MigrationError(f"Execution requires --confirm-source-count {expected_count}.")

    with exclusive_checkpoint_lock(profile.checkpoint_path):
        validate_source_snapshot(profile, manifest)
        checkpoint = load_checkpoint(profile, manifest, create=True)
        save_checkpoint(profile, checkpoint)
        _, service, dependencies = load_authorized_credentials(profile)
        print("authorized_email:", profile.destination)
        print("exact_account_match: true")
        print(
            "known_security_rejection_policy:",
            (
                "local_only_and_continue"
                if continue_known_security_rejections
                else profile.rejection_policy
            ),
        )
        label_map = ensure_gmail_labels(
            profile, manifest, checkpoint, service
        )
        imported_or_accounted_this_run = 0
        rows = row_by_key(manifest)

        for index, manifest_row in enumerate(manifest["messages"], start=1):
            item_key = manifest_row["item_key"]
            row = rows[item_key]
            state = checkpoint["states"][item_key]
            status_value = state["status"]
            if status_value in TERMINAL_STATUSES:
                continue
            if status_value == "duplicate_pending_canonical":
                if not resolve_exact_duplicate_source_row(
                    profile, manifest, checkpoint, row, label_map
                ):
                    report = build_report(profile, manifest, checkpoint)
                    write_json_atomic(profile.report_path, report)
                    print_report(report)
                    print("blocked_item_key:", item_key, file=sys.stderr)
                    print("blocked_relative_path:", row["relative_path"], file=sys.stderr)
                    raise RunBlocked(
                        "STOPPED because an exact source copy is not safely represented by "
                        "its canonical Gmail import."
                    )
                imported_or_accounted_this_run += 1
                continue
            if status_value in {"google_rejected", "preexisting_conflict"}:
                report = build_report(profile, manifest, checkpoint)
                write_json_atomic(profile.report_path, report)
                print_report(report)
                print("blocked_item_key:", item_key, file=sys.stderr)
                print("blocked_relative_path:", row["relative_path"], file=sys.stderr)
                raise RunBlocked(
                    f"STOPPED on status={status_value}; record a reviewed decision before resuming."
                )
            if status_value in {
                "inflight",
                "uncertain",
                "imported_pending_verification",
                "review_required",
                "preexisting_pending_verification",
                "candidate_pending_verification",
            }:
                if not recover_or_verify_existing_state(
                    profile, checkpoint, row, service, label_map
                ):
                    report = build_report(profile, manifest, checkpoint)
                    write_json_atomic(profile.report_path, report)
                    print_report(report)
                    print("blocked_item_key:", item_key, file=sys.stderr)
                    print("blocked_relative_path:", row["relative_path"], file=sys.stderr)
                    raise RunBlocked(
                        "STOPPED because the previous Gmail outcome is not safely resolved."
                    )
                imported_or_accounted_this_run += 1
                continue

            import_args = (
                profile,
                checkpoint,
                row,
                service,
                dependencies,
                label_map,
            )
            if continue_known_security_rejections:
                outcome = import_one(
                    *import_args,
                    continue_known_security_rejections=True,
                )
            else:
                outcome = import_one(*import_args)
            if outcome in {"verified", "local_only"}:
                imported_or_accounted_this_run += 1
            else:
                report = build_report(profile, manifest, checkpoint)
                write_json_atomic(profile.report_path, report)
                print_report(report)
                print("blocked_item_key:", item_key, file=sys.stderr)
                print("blocked_relative_path:", row["relative_path"], file=sys.stderr)
                raise RunBlocked(
                    "STOPPED before the next message; inspect the checkpoint and use review/resume."
                )
            if index % profile.progress_every == 0:
                print(
                    f"progress: {index}/{len(manifest['messages'])} source rows visited; "
                    f"{imported_or_accounted_this_run} newly accounted this run"
                )

        validate_source_snapshot(profile, manifest)
        if not final_reconcile_terminal_gmail(
            profile, manifest, checkpoint, service, label_map
        ):
            report = build_report(profile, manifest, checkpoint)
            write_json_atomic(profile.report_path, report)
            print_report(report)
            raise RunBlocked(
                "STOPPED because final Gmail readback did not verify every covered source row."
            )
        validate_source_snapshot(profile, manifest)
        report = build_report(profile, manifest, checkpoint)
        write_json_atomic(profile.report_path, report)
        print_report(report)
        print("newly_accounted_this_run:", imported_or_accounted_this_run)
        if not report["complete"]:
            raise RunBlocked("Migration ended without a complete source denominator.")
        if not report["gmail_covered_rows_folder_complete"]:
            raise RunBlocked(
                "Every source row is accounted for, but one or more Gmail-covered rows "
                "still lack a frozen source-folder label. Fix those labels, then rerun "
                "with the same stored authorization."
            )
        return 0


def find_review_row(
    manifest: dict[str, Any], item_key: str | None, relative_path: str | None
) -> dict[str, Any]:
    if bool(item_key) == bool(relative_path):
        raise MigrationError("Specify exactly one of --item-key or --relative-path.")
    for row in manifest["messages"]:
        if item_key and row["item_key"] == item_key:
            return row
        if relative_path and row["relative_path"] == relative_path:
            return row
    raise MigrationError("The requested source row is not in the manifest.")


def append_review_history(state: dict[str, Any], decision: str, reason: str) -> None:
    history = state.setdefault("review_history", [])
    if not isinstance(history, list):
        raise MigrationError("Checkpoint review history is invalid.")
    history.append(
        {
            "reviewed_at": utc_now(),
            "previous_status": state.get("status"),
            "decision": decision,
            "reason": reason,
            "previous_http_status": state.get("http_status"),
            "previous_google_error_fingerprint": state.get("google_error_fingerprint"),
            "previous_gmail_message_id": state.get("gmail_message_id", ""),
        }
    )


def cascade_exact_duplicate_dependents_after_final_failure(
    manifest: dict[str, Any],
    checkpoint: dict[str, Any],
    canonical_item_key: str,
    decision: str,
    reason: str,
) -> None:
    for row in manifest["messages"]:
        if row.get("represented_by_item_key") != canonical_item_key:
            continue
        state = checkpoint["states"][row["item_key"]]
        if state.get("status") != "duplicate_source_reviewed":
            continue
        prior = {
            "recorded_at": utc_now(),
            "status": state.get("status"),
            "represented_by_gmail_id": state.get("represented_by_gmail_id"),
            "represented_prepared_sha256": state.get(
                "represented_prepared_sha256"
            ),
            "final_reconciliation_failure": state.get(
                "final_reconciliation_failure"
            ),
        }
        history = state.setdefault("prior_duplicate_representation", [])
        if not isinstance(history, list):
            raise MigrationError("Prior duplicate representation evidence is invalid.")
        history.append(prior)
        append_review_history(state, decision, reason)
        state.pop("represented_by_gmail_id", None)
        state.pop("canonical_union_label_ids", None)
        state.pop("final_readback_verified_at", None)
        state.pop("final_readback_label_ids", None)
        state.pop("final_reconciliation_failure", None)
        if decision == "retry-final-missing":
            state.pop("represented_prepared_sha256", None)
            state.pop("verified_at", None)
            state.update(
                status="duplicate_pending_canonical",
                decision="canonical_missing_reset_duplicate_to_pending",
                decision_reason=reason,
                decided_at=utc_now(),
            )
        else:
            state.update(
                status="duplicate_local_only_reviewed",
                decision="canonical_final_failure_closed_exact_copy_local_only",
                decision_reason=reason,
                decided_at=utc_now(),
                verified_at=utc_now(),
                represented_prepared_sha256=row["prepared_sha256"],
                source_preserved=True,
                resolved_final_reconciliation_failure=prior.get(
                    "final_reconciliation_failure"
                ),
            )


def command_review(
    profile: Profile,
    item_key: str | None,
    relative_path: str | None,
    decision: str,
    reason: str,
    gmail_id: str | None,
    replacement: Path | None,
    confirm_no_gmail_id: bool,
    confirm_source_preserved: bool,
    confirm_gmail_search_zero: bool,
    accept_duplicate_risk: bool,
    confirm_preexisting_not_source_copy: bool,
) -> int:
    if not reason.strip():
        raise MigrationError("A nonempty --reason is required for every review decision.")
    manifest = load_manifest(profile)
    with exclusive_checkpoint_lock(profile.checkpoint_path):
        validate_source_snapshot(profile, manifest)
        checkpoint = load_checkpoint(profile, manifest, create=False)
        row = find_review_row(manifest, item_key, relative_path)
        state = checkpoint["states"][row["item_key"]]
        current_status = state["status"]

        if decision == "retry-final-missing":
            failure = state.get("final_reconciliation_failure")
            if (
                current_status
                not in {"verified", "verified_manual", "preexisting_reviewed"}
                or not isinstance(failure, dict)
                or int(failure.get("http_status", 0) or 0) != 404
                or not state.get("gmail_message_id")
            ):
                raise MigrationError(
                    "retry-final-missing requires a terminal Gmail row whose final exact-ID "
                    "readback recorded HTTP 404."
                )
            if not confirm_gmail_search_zero or not accept_duplicate_risk:
                raise MigrationError(
                    "retry-final-missing requires --confirm-gmail-search-zero and "
                    "--accept-duplicate-risk."
                )
            prior = {
                "recorded_at": utc_now(),
                "status": current_status,
                "gmail_message_id": state.get("gmail_message_id"),
                "verified_at": state.get("verified_at"),
                "returned_label_ids": state.get("returned_label_ids", []),
                "final_reconciliation_failure": failure,
            }
            prior_history = state.setdefault("prior_terminal_gmail_evidence", [])
            if not isinstance(prior_history, list):
                raise MigrationError("Prior terminal Gmail evidence is invalid.")
            prior_history.append(prior)
            append_review_history(state, decision, reason)
            cascade_exact_duplicate_dependents_after_final_failure(
                manifest, checkpoint, row["item_key"], decision, reason
            )
            state.pop("gmail_message_id", None)
            state.pop("gmail_thread_id", None)
            state.pop("final_readback_verified_at", None)
            state.pop("final_reconciliation_failure", None)
            state.update(
                status="pending",
                decision="retry_confirmed_missing_terminal_gmail_row",
                decision_reason=reason,
                decided_at=utc_now(),
                resolved_final_reconciliation_failure=failure,
            )
        elif decision == "local-only-final-failure":
            failure = state.get("final_reconciliation_failure")
            if (
                current_status
                not in {"verified", "verified_manual", "preexisting_reviewed"}
                or not isinstance(failure, dict)
                or not state.get("gmail_message_id")
            ):
                raise MigrationError(
                    "local-only-final-failure requires a terminal Gmail row with a recorded "
                    "final reconciliation failure."
                )
            if not confirm_source_preserved or not accept_duplicate_risk:
                raise MigrationError(
                    "local-only-final-failure requires --confirm-source-preserved and "
                    "--accept-duplicate-risk."
                )
            old_gmail_id = str(state["gmail_message_id"])
            append_review_history(state, decision, reason)
            cascade_exact_duplicate_dependents_after_final_failure(
                manifest, checkpoint, row["item_key"], decision, reason
            )
            state.pop("gmail_message_id", None)
            state.pop("gmail_thread_id", None)
            state.pop("final_readback_verified_at", None)
            state.pop("final_reconciliation_failure", None)
            state.update(
                status="local_only_reviewed",
                decision="terminal_gmail_failure_closed_local_only",
                decision_reason=reason,
                decided_at=utc_now(),
                previous_terminal_gmail_id=old_gmail_id,
                resolved_final_reconciliation_failure=failure,
                source_preserved=True,
            )
        elif decision == "local-only":
            if current_status != "google_rejected":
                raise MigrationError("local-only is allowed only for a definite Google rejection.")
            if state.get("gmail_message_id") or not confirm_no_gmail_id:
                raise MigrationError(
                    "Confirm the rejection recorded no Gmail ID with --confirm-no-gmail-id."
                )
            append_review_history(state, decision, reason)
            state.update(
                status="local_only_reviewed",
                decision="local_only",
                decision_reason=reason,
                decided_at=utc_now(),
                source_preserved=True,
            )
        elif decision == "retry-original":
            if current_status != "google_rejected":
                raise MigrationError("retry-original is allowed only for a definite Google rejection.")
            if state.get("gmail_message_id") or not confirm_no_gmail_id:
                raise MigrationError(
                    "Confirm the rejection recorded no Gmail ID with --confirm-no-gmail-id."
                )
            append_review_history(state, decision, reason)
            state.pop("replacement", None)
            state.update(
                status="pending",
                decision="retry_original",
                decision_reason=reason,
                decided_at=utc_now(),
            )
        elif decision == "use-replacement":
            if current_status != "google_rejected":
                raise MigrationError("use-replacement is allowed only for a definite Google rejection.")
            if replacement is None or not confirm_source_preserved or not confirm_no_gmail_id:
                raise MigrationError(
                    "use-replacement requires --replacement, --confirm-source-preserved, and "
                    "--confirm-no-gmail-id."
                )
            replacement_path = replacement.expanduser().resolve()
            replacements_root = (profile.state_dir / "replacements").resolve()
            if not replacement_path.is_file() or not is_within(
                replacement_path, replacements_root
            ):
                raise MigrationError(
                    f"Replacement must be a file below {replacements_root}."
                )
            _, observed = parse_source_path(replacement_path, replacements_root)
            if observed["message_id"] != row["message_id"]:
                raise MigrationError("Replacement Message-ID must match the source.")
            if observed["date_header"] != row["date_header"]:
                raise MigrationError("Replacement Date header must match the source.")
            append_review_history(state, decision, reason)
            state.update(
                status="pending",
                decision="use_replacement",
                decision_reason=reason,
                decided_at=utc_now(),
                replacement={
                    "path": str(replacement_path),
                    "source_sha256": observed["source_sha256"],
                    "prepared_sha256": observed["prepared_sha256"],
                    "reviewed_at": utc_now(),
                    "source_original_preserved": True,
                },
            )
        elif decision == "accept-preexisting":
            if current_status != "preexisting_conflict":
                raise MigrationError(
                    "accept-preexisting is allowed only for a preexisting conflict."
                )
            candidates = {str(item) for item in state.get("preexisting_gmail_ids", [])}
            if not gmail_id or gmail_id not in candidates:
                raise MigrationError("--gmail-id must name one recorded preexisting candidate.")
            unselected = sorted(candidates - {gmail_id})
            if unselected and not accept_duplicate_risk:
                raise MigrationError(
                    "Selecting one of multiple preexisting candidates requires "
                    "--accept-duplicate-risk."
                )
            append_review_history(state, decision, reason)
            state.update(
                status="preexisting_pending_verification",
                decision="verify_preexisting",
                decision_reason=reason,
                decided_at=utc_now(),
                gmail_message_id=gmail_id,
                unselected_candidate_ids=unselected,
                unselected_candidates_reviewed=bool(unselected),
            )
        elif decision == "ignore-preexisting":
            if current_status != "preexisting_conflict" and not (
                current_status == "review_required"
                and state.get("review_origin") == "preexisting_candidate"
            ):
                raise MigrationError(
                    "ignore-preexisting is allowed only for a preexisting conflict or its "
                    "failed candidate readback."
                )
            if not confirm_preexisting_not_source_copy or not accept_duplicate_risk:
                raise MigrationError(
                    "ignore-preexisting requires --confirm-preexisting-not-source-copy and "
                    "--accept-duplicate-risk."
                )
            candidates = [
                str(item) for item in state.get("preexisting_gmail_ids", [])
            ]
            if state.get("gmail_message_id"):
                candidates.append(str(state["gmail_message_id"]))
            candidates = sorted(set(candidates))
            if not candidates:
                raise MigrationError("No preexisting candidates are recorded.")
            append_review_history(state, decision, reason)
            state.pop("gmail_message_id", None)
            state.update(
                status="pending",
                decision="ignore_preexisting_and_import",
                decision_reason=reason,
                decided_at=utc_now(),
                ignored_preexisting_gmail_ids=candidates,
            )
        elif decision == "retry-uncertain":
            if current_status != "uncertain":
                raise MigrationError("retry-uncertain is allowed only for an uncertain row.")
            observations = state.get("reconciliation_observations", [])
            if (
                not isinstance(observations, list)
                or not observations
                or observations[-1].get("new_candidate_ids")
            ):
                raise MigrationError(
                    "retry-uncertain requires a recorded latest zero-candidate reconciliation."
                )
            if not confirm_gmail_search_zero or not accept_duplicate_risk:
                raise MigrationError(
                    "retry-uncertain requires --confirm-gmail-search-zero and "
                    "--accept-duplicate-risk."
                )
            append_review_history(state, decision, reason)
            state.update(
                status="pending",
                decision="retry_after_reviewed_uncertainty",
                decision_reason=reason,
                decided_at=utc_now(),
                gmail_message_id="",
            )
        elif decision == "local-only-conflict":
            if (
                current_status != "review_required"
                or not state.get("conflicting_gmail_message_id")
                or not accept_duplicate_risk
            ):
                raise MigrationError(
                    "local-only-conflict requires a recorded conflicting Gmail ID and "
                    "--accept-duplicate-risk."
                )
            append_review_history(state, decision, reason)
            state.pop("gmail_message_id", None)
            state.update(
                status="local_only_reviewed",
                decision="source_row_not_separately_represented_after_gmail_id_conflict",
                decision_reason=reason,
                decided_at=utc_now(),
                source_preserved=True,
            )
        elif decision == "local-only-duplicate":
            if (
                current_status != "duplicate_pending_canonical"
                or row.get("action") != "merge_exact_duplicate"
                or not accept_duplicate_risk
            ):
                raise MigrationError(
                    "local-only-duplicate requires a blocked exact-copy row and "
                    "--accept-duplicate-risk."
                )
            append_review_history(state, decision, reason)
            state.update(
                status="duplicate_local_only_reviewed",
                decision="reviewed_exact_copy_not_proven_as_separate_gmail_coverage",
                decision_reason=reason,
                decided_at=utc_now(),
                verified_at=utc_now(),
                represented_prepared_sha256=row["prepared_sha256"],
                source_preserved=True,
            )
        elif decision == "accept-candidate":
            if current_status != "review_required" or state.get("gmail_message_id"):
                raise MigrationError(
                    "accept-candidate requires review_required without an assigned Gmail ID."
                )
            candidate_ids = {
                str(candidate)
                for observation in state.get("reconciliation_observations", [])
                if isinstance(observation, dict)
                for candidate in observation.get("new_candidate_ids", [])
            }
            if not gmail_id or gmail_id not in candidate_ids:
                raise MigrationError(
                    "--gmail-id must name one recorded reconciliation candidate."
                )
            if not accept_duplicate_risk:
                raise MigrationError(
                    "Selecting one of multiple reconciliation candidates requires "
                    "--accept-duplicate-risk."
                )
            unselected = sorted(candidate_ids - {gmail_id})
            append_review_history(state, decision, reason)
            state.update(
                status="candidate_pending_verification",
                decision="verify_reconciliation_candidate",
                decision_reason=reason,
                decided_at=utc_now(),
                gmail_message_id=gmail_id,
                unselected_candidate_ids=unselected,
                unselected_candidates_reviewed=True,
            )
        elif decision == "accept-imported":
            if current_status != "review_required" or not state.get(
                "gmail_message_id"
            ):
                raise MigrationError(
                    "accept-imported requires review_required with a recorded Gmail ID."
                )
            if gmail_id != state.get("gmail_message_id"):
                raise MigrationError("--gmail-id must match the recorded Gmail ID.")
            append_review_history(state, decision, reason)
            state.update(
                status="verified_manual",
                decision="accept_imported_after_manual_readback",
                decision_reason=reason,
                decided_at=utc_now(),
                verified_at=utc_now(),
            )
        else:
            raise MigrationError(f"Unsupported review decision: {decision}")

        save_checkpoint(profile, checkpoint)
        report = build_report(profile, manifest, checkpoint)
        write_json_atomic(profile.report_path, report)
        print("review_decision_recorded: true")
        print("item_key:", row["item_key"])
        print("relative_path:", row["relative_path"])
        print("new_status:", state["status"])
        print("source_preserved: true")
        print_report(report)
        return 0


def command_status(profile: Profile) -> int:
    manifest = load_manifest(profile)
    validate_source_snapshot(profile, manifest)
    checkpoint = (
        load_checkpoint(profile, manifest, create=False)
        if profile.checkpoint_path.exists()
        else None
    )
    report = build_report(profile, manifest, checkpoint)
    print_report(report)
    if profile.report_path.exists():
        print("report:", profile.report_path)
    print("token_store:", token_store_description(profile))
    print("token_present:", str(load_token_json(profile) is not None).lower())
    return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare = subparsers.add_parser("prepare", help="Inventory every source EML.")
    prepare.add_argument("--profile", type=Path, required=True)
    prepare.add_argument("--replace", action="store_true")

    authorize = subparsers.add_parser(
        "authorize", help="Perform the one interactive offline OAuth grant."
    )
    authorize.add_argument("--profile", type=Path, required=True)
    authorize.add_argument("--reauthorize", action="store_true")

    run = subparsers.add_parser(
        "run", help="Process all pending EML rows until complete or safely blocked."
    )
    run.add_argument("--profile", type=Path, required=True)
    run.add_argument("--confirm-destination", required=True)
    run.add_argument("--confirm-source-count", type=int, required=True)
    run.add_argument(
        "--continue-known-security-rejections-local-only",
        action="store_true",
        help=(
            "For the exact allowlisted Gmail Invalid attachment response only, "
            "record the preserved source as local-only and continue."
        ),
    )

    status_parser = subparsers.add_parser("status", help="Show the exact denominator.")
    status_parser.add_argument("--profile", type=Path, required=True)

    review = subparsers.add_parser(
        "review", help="Record a bounded decision after a safe stop."
    )
    review.add_argument("--profile", type=Path, required=True)
    target = review.add_mutually_exclusive_group(required=True)
    target.add_argument("--item-key")
    target.add_argument("--relative-path")
    review.add_argument(
        "--decision",
        required=True,
        choices=(
            "retry-final-missing",
            "local-only-final-failure",
            "local-only",
            "retry-original",
            "use-replacement",
            "accept-preexisting",
            "ignore-preexisting",
            "retry-uncertain",
            "local-only-conflict",
            "local-only-duplicate",
            "accept-candidate",
            "accept-imported",
        ),
    )
    review.add_argument("--reason", required=True)
    review.add_argument("--gmail-id")
    review.add_argument("--replacement", type=Path)
    review.add_argument("--confirm-no-gmail-id", action="store_true")
    review.add_argument("--confirm-source-preserved", action="store_true")
    review.add_argument("--confirm-gmail-search-zero", action="store_true")
    review.add_argument("--accept-duplicate-risk", action="store_true")
    review.add_argument(
        "--confirm-preexisting-not-source-copy", action="store_true"
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        profile = load_profile(args.profile)
        if args.command == "prepare":
            return command_prepare(profile, args.replace)
        if args.command == "authorize":
            return command_authorize(profile, args.reauthorize)
        if args.command == "run":
            return command_run(
                profile,
                args.confirm_destination,
                args.confirm_source_count,
                args.continue_known_security_rejections_local_only,
            )
        if args.command == "status":
            return command_status(profile)
        if args.command == "review":
            return command_review(
                profile,
                args.item_key,
                args.relative_path,
                args.decision,
                args.reason,
                args.gmail_id,
                args.replacement,
                args.confirm_no_gmail_id,
                args.confirm_source_preserved,
                args.confirm_gmail_search_zero,
                args.accept_duplicate_risk,
                args.confirm_preexisting_not_source_copy,
            )
        raise MigrationError(f"Unknown command: {args.command}")
    except AuthRequired as exc:
        print(f"AUTH_REQUIRED: {exc}", file=sys.stderr)
        print("gmail_writes_after_stop: 0", file=sys.stderr)
        return 3
    except RunBlocked as exc:
        print(str(exc), file=sys.stderr)
        print("No later source rows were attempted.", file=sys.stderr)
        return 4
    except MigrationError as exc:
        print(f"STOPPED: {exc}", file=sys.stderr)
        print("No further Gmail writes were attempted.", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("STOPPED: interrupted by the operator.", file=sys.stderr)
        print("No further Gmail writes were attempted.", file=sys.stderr)
        return 130
    except Exception as exc:
        # Keep unattended runs fail-closed even when a library returns an
        # unanticipated exception. Never print object reprs that could include
        # request headers or OAuth credentials.
        print(
            f"STOPPED: unexpected {type(exc).__name__}; inspect the local checkpoint and tests.",
            file=sys.stderr,
        )
        print("No further Gmail writes were attempted.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
