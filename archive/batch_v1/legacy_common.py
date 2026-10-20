# Sanitized historical reference: source-specific evidence and live configuration are not distributed.
#!/usr/bin/env python3
'Shared, deterministic EML normalization for the mailbox Inbox archive.'

from __future__ import annotations

import hashlib
import re
from datetime import timezone
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any


SOURCE_ROOT = Path('/private/migration-example/source-export')
SOURCE_FOLDER = 'source-export'
SOURCE_COUNT = 2005
SOURCE_BYTES = 1_224_550_180
DESTINATION = 'example-b54b38f4@example.org'
OAUTH_CLIENT_ID = (
    'example-client.apps.googleusercontent.com'
)

RECEIVED_FOLD_PREFIX = b"by webmail-030.cafe24.com with "
EXPECTED_RECEIVED_REPAIR_COUNT = 229
EXPECTED_RECEIVED_REPAIR_ID_DIGEST = (
    '0000000000000000000000000000000000000000000000000000000000002225'
)
DATE_UTC_NORMALIZATION_IDS = {971, 1410, 1472}
DUPLICATE_SKIP_TO_KEEP = {1207: 1198, 1662: 1661, 714: 715}
EXPECTED_DUPLICATE_GROUPS = {
    frozenset((714, 715)),
    frozenset((1198, 1207)),
    frozenset((1661, 1662)),
}


class ArchiveError(RuntimeError):
    """Raised when the source archive no longer matches the audited archive."""


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def numeric_id(path_or_name: str | Path) -> int:
    name = Path(path_or_name).name
    match = re.match(r"^(\d+)\.", name)
    if not match:
        raise ArchiveError(f"Source filename lacks a numeric prefix: {name}")
    return int(match.group(1))


def all_defects(message) -> list[str]:
    defects: list[str] = []
    for part in message.walk():
        defects.extend(type(item).__name__ for item in part.defects)
    return defects


def _repair_received_fold(raw: bytes) -> tuple[bytes, bool]:
    message = BytesParser(policy=policy.default).parsebytes(raw)
    defects = all_defects(message)
    if not defects:
        return raw, False
    if defects != ["MissingHeaderBodySeparatorDefect"]:
        raise ArchiveError(f"Unexpected parser defects: {defects}")

    lines = raw.splitlines(keepends=True)
    if len(lines) < 3:
        raise ArchiveError("Malformed EML is too short for the audited repair.")
    if not lines[0].lower().startswith(b"received:"):
        raise ArchiveError("Malformed EML does not start with Received.")
    if not lines[1].startswith(RECEIVED_FOLD_PREFIX):
        raise ArchiveError("Malformed EML does not match the Cafe24 fold signature.")
    if not lines[2].lower().startswith(b"mime-version:"):
        raise ArchiveError("Malformed EML does not match the audited third-line signature.")
    lines[1] = b" " + lines[1]
    return b"".join(lines), True


def normalize_eml(raw: bytes, source_id: int) -> tuple[bytes, list[str]]:
    """Return import bytes and an ordered list of applied staging-only repairs."""
    prepared, received_repaired = _repair_received_fold(raw)
    repairs = []
    if received_repaired:
        repairs.append("cafe24_received_fold_space_v1")
    return prepared, repairs


def parse_prepared(prepared: bytes, source_id: int) -> dict[str, Any]:
    message = BytesParser(policy=policy.default).parsebytes(prepared)
    defects = all_defects(message)
    if defects:
        raise ArchiveError(f"Prepared source {source_id} has defects: {defects}")

    message_id = str(message.get("Message-ID", "")).strip()
    date_header = str(message.get("Date", "")).strip()
    if not message_id or not date_header:
        raise ArchiveError(f"Prepared source {source_id} lacks Message-ID or Date.")
    try:
        parsed_date = parsedate_to_datetime(date_header)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ArchiveError(f"Prepared source {source_id} has an invalid Date.") from exc
    date_policy = "rfc5322_offset"
    if parsed_date.tzinfo is None:
        if source_id not in DATE_UTC_NORMALIZATION_IDS or not date_header.endswith("-0000"):
            raise ArchiveError(f"Prepared source {source_id} lacks an audited Date timezone.")
        # RFC 5322 -0000 expresses UTC while withholding the sender's local zone.
        # Preserve the signed Date header byte-for-byte and use UTC for comparison.
        parsed_date = parsed_date.replace(tzinfo=timezone.utc)
        date_policy = "rfc5322_minus0000_preserved_interpreted_as_utc"

    header_separator = b"\r\n\r\n" if b"\r\n\r\n" in prepared else b"\n\n"
    parts = prepared.split(header_separator, 1)
    if len(parts) != 2:
        raise ArchiveError(f"Prepared source {source_id} lacks a header/body separator.")

    return {
        "message_id": message_id,
        "date_header": date_header,
        "expected_internal_date_ms": int(parsed_date.timestamp() * 1000),
        "date_policy": date_policy,
        "body_sha256": sha256_bytes(parts[1]),
        "from_header": str(message.get("From", "")).strip(),
        "to_header": str(message.get("To", "")).strip(),
        "cc_header": str(message.get("Cc", "")).strip(),
        "subject_header": str(message.get("Subject", "")).strip(),
        "missing_to": message.get("To") is None,
        "missing_subject": message.get("Subject") is None,
        "message_id_canonical": (
            message_id.startswith("<") and message_id.endswith(">") and "@" in message_id
        ),
    }


def prepared_record(path: Path) -> tuple[bytes, dict[str, Any]]:
    source_id = numeric_id(path)
    raw = path.read_bytes()
    prepared, repairs = normalize_eml(raw, source_id)
    parsed = parse_prepared(prepared, source_id)
    record = {
        "source_id": source_id,
        "relative_path": path.name,
        "source_size_bytes": len(raw),
        "source_sha256": sha256_bytes(raw),
        "prepared_size_bytes": len(prepared),
        "prepared_sha256": sha256_bytes(prepared),
        "repairs": repairs,
        **parsed,
    }
    return prepared, record


def archive_files() -> list[Path]:
    if not SOURCE_ROOT.is_dir() or SOURCE_ROOT.name != SOURCE_FOLDER:
        raise ArchiveError("The audited Cafe24 source folder is missing.")
    paths = sorted(SOURCE_ROOT.glob("*.eml"), key=numeric_id)
    if len(paths) != SOURCE_COUNT:
        raise ArchiveError(f"Expected {SOURCE_COUNT} EML files, found {len(paths)}.")
    ids = [numeric_id(path) for path in paths]
    if ids != list(range(1, SOURCE_COUNT + 1)):
        raise ArchiveError("Source numeric IDs are no longer exactly 1 through 2005.")
    total_bytes = sum(path.stat().st_size for path in paths)
    if total_bytes != SOURCE_BYTES:
        raise ArchiveError(
            f"Expected {SOURCE_BYTES} source bytes, found {total_bytes}."
        )
    return paths
