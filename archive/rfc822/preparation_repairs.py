# Sanitized historical reference: source-specific evidence and live configuration are not distributed.
"""One source-fingerprint-bound MIME repair; originals are never modified.

Source 625 uses base64 for a message/rfc822 attachment. Python's email parser
does not decode that container and sees base64 as malformed nested headers.
Convert only that container's transfer representation to 8bit, preserving the
decoded attached EML byte for byte and every byte outside the two exact ranges.
"""
from __future__ import annotations

import base64
import hashlib
import re
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Callable, Any

SOURCE_SHA256 = '00000000000000000000000000000000000000000000000000000000000035b4'
PREPARED_SHA256 = '000000000000000000000000000000000000000000000000000000000000c010'
ATTACHMENT_SHA256 = '000000000000000000000000000000000000000000000000000000000000dc94'
SOURCE_SIZE = 29564
PREPARED_SIZE = 23810
CTE_RANGE = (8097, 8130)
PAYLOAD_RANGE = (8134, 29498)
OLD_CTE = b"Content-Transfer-Encoding: base64"
NEW_CTE = b"Content-Transfer-Encoding: 8bit"
REPAIR_NAME = 'rfc822_exact_sha256_rfc822_base64_to_8bit_v1'
SOURCE_DEFECTS = ["MissingHeaderBodySeparatorDefect"]

# One later delivery of exactly the same authored message is represented by its
# earlier delivery. Both immutable EML originals and their source hashes remain
# in the manifest. The shared engine then performs its exact-prepared-byte merge.
CANONICAL_SOURCE_PATH = Path('/private/migration-example/message.eml')
CANONICAL_SOURCE_SHA256 = '0000000000000000000000000000000000000000000000000000000000003686'
DUPLICATE_SOURCE_SHA256 = '000000000000000000000000000000000000000000000000000000000000feb1'
DUPLICATE_REPAIR_NAME = 'rfc822_exact_sha256_duplicate_delivery_805_to_804_v1'
TRANSPORT_HEADERS = frozenset({b"received", b"received-spf", b"arc-seal", b"arc-message-signature", b"x-spamfilter-score"})


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def defects(message: Any) -> list[str]:
    return [type(d).__name__ for part in message.walk() for d in part.defects]


def raw_header_fields_and_body(raw: bytes) -> tuple[list[tuple[bytes, bytes]], bytes]:
    """Keep byte-exact field blocks, including order and folding, plus body."""
    header, separator, body = raw.partition(b"\r\n\r\n")
    if not separator:
        raise ValueError("Audited duplicate source lacks the expected separator.")
    fields: list[tuple[bytes, bytes]] = []
    for line in header.split(b"\r\n"):
        if line[:1] in (b" ", b"\t"):
            if not fields:
                raise ValueError("Unexpected initial folded header.")
            name, value = fields[-1]
            fields[-1] = (name, value + b"\r\n" + line)
        else:
            if not re.match(rb"^[!-9;-~]+:", line):
                raise ValueError("Unexpected malformed header in duplicate source.")
            fields.append((line.split(b":", 1)[0].lower(), line))
    return fields, body


def validate_duplicate_content_equivalence(raw: bytes, canonical: bytes) -> None:
    source_fields, source_body = raw_header_fields_and_body(raw)
    canonical_fields, canonical_body = raw_header_fields_and_body(canonical)
    if source_body != canonical_body:
        raise ValueError("Duplicate delivery MIME body differs from canonical.")
    source_authored = [(k, v) for k, v in source_fields if k not in TRANSPORT_HEADERS]
    canonical_authored = [(k, v) for k, v in canonical_fields if k not in TRANSPORT_HEADERS]
    if source_authored != canonical_authored:
        raise ValueError("Duplicate delivery protected raw headers differ.")
    # Only the final delivery hop changes; upstream queue IDs and route match.
    source_received = [v for k, v in source_fields if k == b"received"]
    canonical_received = [v for k, v in canonical_fields if k == b"received"]
    if len(source_received) != 3 or len(canonical_received) != 3 or source_received[1:] != canonical_received[1:]:
        raise ValueError("Duplicate delivery upstream Received headers differ.")
    for message in (raw, canonical):
        if defects(BytesParser(policy=policy.default).parsebytes(message)):
            raise ValueError("Duplicate delivery has unexpected parser defects.")


def canonicalize_exact_duplicate(raw: bytes) -> bytes | None:
    if sha256(raw) != DUPLICATE_SOURCE_SHA256:
        return None
    canonical = CANONICAL_SOURCE_PATH.read_bytes()
    if sha256(canonical) != CANONICAL_SOURCE_SHA256:
        raise ValueError("Audited canonical source 804 hash differs.")
    validate_duplicate_content_equivalence(raw, canonical)
    return canonical


def repair_exact_source(raw: bytes) -> bytes | None:
    """Return repaired bytes only for the one audited source, else None."""
    if sha256(raw) != SOURCE_SHA256:
        return None
    if len(raw) != SOURCE_SIZE or raw[slice(*CTE_RANGE)] != OLD_CTE:
        raise ValueError("Audited source 625 byte-range assertions failed.")
    original_message = BytesParser(policy=policy.default).parsebytes(raw)
    if defects(original_message) != SOURCE_DEFECTS:
        raise ValueError("Audited source 625 parser defects changed.")
    attachment = original_message.get_payload()[1]
    if attachment.get_content_type() != "message/rfc822":
        raise ValueError("Audited source 625 attachment MIME type changed.")
    encoded = raw[slice(*PAYLOAD_RANGE)]
    decoded = base64.b64decode(re.sub(rb"\s", b"", encoded), validate=True)
    if len(decoded) != 15612 or sha256(decoded) != ATTACHMENT_SHA256:
        raise ValueError("Audited source 625 decoded attachment differs.")
    boundary = b"--" + original_message.get_boundary().encode("ascii")
    if boundary in decoded:
        raise ValueError("Decoded attachment collides with outer MIME boundary.")
    nested = BytesParser(policy=policy.default).parsebytes(decoded)
    if defects(nested):
        raise ValueError("Decoded attachment contains parser defects.")
    prepared = (
        raw[:CTE_RANGE[0]] + NEW_CTE
        + raw[CTE_RANGE[1]:PAYLOAD_RANGE[0]]
        + decoded + raw[PAYLOAD_RANGE[1]:]
    )
    if len(prepared) != PREPARED_SIZE or sha256(prepared) != PREPARED_SHA256:
        raise ValueError("Audited source 625 prepared hash differs.")
    if defects(BytesParser(policy=policy.default).parsebytes(prepared)):
        raise ValueError("Audited source 625 repair left parser defects.")
    return prepared


def prepare_source_bytes(raw: bytes, original_prepare: Callable) -> tuple:
    """Adapter for engine.prepare_source_bytes; delegate every other source."""
    canonical = canonicalize_exact_duplicate(raw)
    if canonical is not None:
        checked, repairs, occurrences, previous_defects = original_prepare(canonical)
        if checked != canonical or repairs or occurrences or previous_defects:
            raise ValueError("Canonical source 804 unexpectedly requires repair.")
        return canonical, [DUPLICATE_REPAIR_NAME], {DUPLICATE_REPAIR_NAME: 1}, []
    prepared = repair_exact_source(raw)
    if prepared is None:
        return original_prepare(raw)
    checked, repairs, occurrences, previous_defects = original_prepare(prepared)
    if checked != prepared or repairs or occurrences or previous_defects:
        raise ValueError("Audited source 625 unexpectedly needs another repair.")
    return prepared, [REPAIR_NAME], {REPAIR_NAME: 1}, list(SOURCE_DEFECTS)
