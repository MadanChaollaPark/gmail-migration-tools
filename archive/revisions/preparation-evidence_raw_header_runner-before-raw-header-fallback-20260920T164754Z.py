# Sanitized historical reference: source-specific evidence and live configuration are not distributed.
#!/usr/bin/env python3
'Raw-header adapter for the shared source-preserving Gmail migration engine.\n\nOnly one immutable source fingerprint receives the audited multipart-header\nrepair. The shared engine retains account, checkpoint, source, and readback\ncontrols. SG_PILOT_LIMIT optionally stops before the next import after N\nverified import_one outcomes in this process; unset it to resume normally.\n'

from __future__ import annotations

import functools
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import sys
from typing import Any, Callable


ENGINE_PATH = next(p / "gmail_eml_migration_v2.py" for p in Path(__file__).resolve().parents if (p / "gmail_eml_migration_v2.py").is_file())
AUDITED_SOURCE_SHA256 = '000000000000000000000000000000000000000000000000000000000000d36f'
AUDITED_PREPARED_SHA256 = '000000000000000000000000000000000000000000000000000000000000fd0c'
REPAIR_NAME = "sg_exact_sha256_multipart_container_cte_removal_v1"
AUDITED_RANGES = ((1199, 1244), (2859, 2904))
AUDITED_HEADER = b"Content-Transfer-Encoding: quoted-printable\r\n"
AUDITED_DEFECTS = ["InvalidMultipartContentTransferEncodingDefect"] * 2

_spec = importlib.util.spec_from_file_location("_sg_shared_migration_engine", ENGINE_PATH)
if _spec is None or _spec.loader is None:
    raise RuntimeError("Cannot load the shared migration engine.")
engine = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = engine
_spec.loader.exec_module(engine)
_original_prepare_source_bytes = engine.prepare_source_bytes
_original_import_one = engine.import_one


def prepare_source_bytes(raw: bytes) -> tuple[bytes, list[str], dict[str, int], list[str]]:
    if hashlib.sha256(raw).hexdigest() != AUDITED_SOURCE_SHA256:
        return _original_prepare_source_bytes(raw)

    original = engine.BytesParser(policy=engine.policy.default).parsebytes(raw)
    original_defects = engine.collect_defects(original)
    if original_defects != AUDITED_DEFECTS:
        raise engine.MigrationError('Audited Raw-header source parser defects changed.')
    prepared = raw
    for start, end in reversed(AUDITED_RANGES):
        if raw[start:end] != AUDITED_HEADER:
            raise engine.MigrationError('Audited Raw-header container header bytes changed.')
        prepared = prepared[:start] + prepared[end:]
    if hashlib.sha256(prepared).hexdigest() != AUDITED_PREPARED_SHA256:
        raise engine.MigrationError('Audited Raw-header prepared fingerprint mismatch.')
    parsed = engine.BytesParser(policy=engine.policy.default).parsebytes(prepared)
    if engine.collect_defects(parsed) or sum(1 for _ in parsed.walk()) != 4:
        raise engine.MigrationError('Audited Raw-header prepared MIME validation failed.')
    return prepared, [REPAIR_NAME], {REPAIR_NAME: 2}, original_defects


def make_pilot_importer(original: Callable[..., str], limit: int) -> Callable[..., str]:
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
        raise engine.MigrationError("SG_PILOT_LIMIT must be a nonnegative integer.")
    verified = 0

    @functools.wraps(original)
    def import_one(*args: Any, **kwargs: Any) -> str:
        nonlocal verified
        if verified >= limit:
            raise engine.MigrationError("Pilot complete; resume same checkpoint")
        outcome = original(*args, **kwargs)
        if outcome == "verified":
            verified += 1
        return outcome

    return import_one


engine.prepare_source_bytes = prepare_source_bytes


def main(argv: list[str] | None = None) -> int:
    pilot_value = os.environ.get("SG_PILOT_LIMIT")
    engine.import_one = _original_import_one
    if pilot_value is not None:
        if not re.fullmatch(r"[0-9]+", pilot_value):
            print("STOPPED: SG_PILOT_LIMIT must be a nonnegative integer.", file=sys.stderr)
            return 2
        engine.import_one = make_pilot_importer(_original_import_one, int(pilot_value))
    return engine.main(argv)


if __name__ == "__main__":
    raise SystemExit("Archived reference variant. Use the configurable v2 engine at the repository root.")
    raise SystemExit(main())
