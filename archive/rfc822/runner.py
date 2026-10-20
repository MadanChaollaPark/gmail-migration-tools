# Sanitized historical reference: source-specific evidence and live configuration are not distributed.
#!/usr/bin/env python3
'Mailbox-scoped adapter with one fingerprint-bound MIME representation repair.\n\nRFC822_PILOT_LIMIT=5 caps calls to import_one before the sixth can begin.\nUnset it to resume the same checkpoint after checking the pilot receipts.\nThe shared engine still checks the source snapshot, Gmail account, and every\nreceipt. A global destination lock supplements its checkpoint lock.\n'

from __future__ import annotations

from contextlib import contextmanager
import fcntl
import functools
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import sys
from typing import Any, Callable, Iterator

import preparation_repairs


ENGINE_PATH = next(p / "gmail_eml_migration_v2.py" for p in Path(__file__).resolve().parents if (p / "gmail_eml_migration_v2.py").is_file())
EXPECTED_SOURCE_MAILBOX = 'example-49d20801@example.org'
EXPECTED_DESTINATION = 'example-49d20801@example.org'
DESTINATION_LOCK_DIR = Path('/private/migration-example/destination-locks')

_spec = importlib.util.spec_from_file_location('_rfc822_shared_migration_engine', ENGINE_PATH)
if _spec is None or _spec.loader is None:
    raise RuntimeError("Cannot load the shared migration engine.")
engine = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = engine
_spec.loader.exec_module(engine)
_original_load_profile = engine.load_profile
_original_load_checkpoint = engine.load_checkpoint
_original_save_state = engine.save_state
_original_import_one = engine.import_one
_original_prepare_source_bytes = engine.prepare_source_bytes


class PilotComplete(engine.MigrationError):
    """Expected stop before an additional pilot import begins."""


def prepare_source_bytes(raw: bytes) -> tuple:
    try:
        return preparation_repairs.prepare_source_bytes(raw, _original_prepare_source_bytes)
    except ValueError as exc:
        raise engine.MigrationError('The fingerprint-bound rfc822 MIME repair failed validation.') from exc


def guard_profile(profile: Any) -> None:
    if profile.destination != EXPECTED_DESTINATION or profile.source_mailbox != EXPECTED_SOURCE_MAILBOX:
        raise engine.MigrationError(
            f"This adapter requires source {EXPECTED_SOURCE_MAILBOX} and destination {EXPECTED_DESTINATION}."
        )


def load_profile(path: Path) -> Any:
    profile = _original_load_profile(path)
    guard_profile(profile)
    return profile


def load_checkpoint(profile: Any, manifest: dict[str, Any], create: bool = False) -> dict[str, Any]:
    guard_profile(profile)
    checkpoint = _original_load_checkpoint(profile, manifest, create=create)
    if any(state.get("status") == "verified_manual" for state in checkpoint["states"].values()):
        raise engine.MigrationError("This adapter does not accept manual readback exemptions.")
    return checkpoint


def save_state(profile: Any, checkpoint: dict[str, Any], item_key: str, **updates: Any) -> None:
    """Preserve an actual transport error in the field the shared loader reads.

    HTTP status zero remains zero, and the state remains uncertain. This is an
    evidence-schema fix only: it neither selects a candidate nor retries mail.
    """
    guard_profile(profile)
    merged = {**checkpoint["states"][item_key], **updates}
    recognized = any(merged.get(field) for field in (
        "error", "error_type", "reconciliation_observations", "http_status"
    ))
    google_error = merged.get("google_error")
    if (
        merged.get("status") == "uncertain"
        and merged.get("google_error_fingerprint")
        and not recognized
        and isinstance(google_error, str)
        and google_error.strip()
    ):
        updates = {**updates, "error": google_error}
    _original_save_state(profile, checkpoint, item_key, **updates)


@contextmanager
def destination_lock(profile: Any) -> Iterator[None]:
    guard_profile(profile)
    DESTINATION_LOCK_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    digest = hashlib.sha256(profile.destination.encode("utf-8")).hexdigest()
    path = DESTINATION_LOCK_DIR / f"{digest}.lock"
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "r+", encoding="utf-8") as handle:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise engine.MigrationError(f"Another process holds the destination lock for {profile.destination}.") from exc
        try:
            handle.seek(0)
            handle.truncate()
            handle.write(f"destination={profile.destination} pid={os.getpid()} locked_at={engine.utc_now()}\n")
            handle.flush()
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def make_pilot_importer(original: Callable[..., str], limit: int) -> Callable[..., str]:
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
        raise engine.MigrationError('RFC822_PILOT_LIMIT must be a nonnegative integer.')
    started = 0

    @functools.wraps(original)
    def import_one(*args: Any, **kwargs: Any) -> str:
        nonlocal started
        if started >= limit:
            raise PilotComplete(f"Pilot boundary reached after {started} import calls; verify receipts and resume the same checkpoint.")
        started += 1
        return original(*args, **kwargs)

    return import_one


engine.load_profile = load_profile
engine.load_checkpoint = load_checkpoint
engine.save_state = save_state
engine.prepare_source_bytes = prepare_source_bytes


def main(argv: list[str] | None = None) -> int:
    effective_argv = list(argv) if argv is not None else sys.argv[1:]
    args = engine.parse_args(effective_argv)
    try:
        profile = load_profile(args.profile)
        engine.import_one = _original_import_one
        pilot_value = os.environ.get('RFC822_PILOT_LIMIT')
        if pilot_value is not None:
            if not re.fullmatch(r"[0-9]+", pilot_value):
                raise engine.MigrationError('RFC822_PILOT_LIMIT must be a nonnegative integer.')
            engine.import_one = make_pilot_importer(_original_import_one, int(pilot_value))
        if args.command == "review" and args.decision == "accept-imported":
            raise engine.MigrationError("This adapter does not permit manual readback exemptions.")
        if args.command in {"run", "review", "authorize"}:
            with destination_lock(profile):
                return engine.main(effective_argv)
        return engine.main(effective_argv)
    except engine.MigrationError as exc:
        print(f"STOPPED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit("Archived reference variant. Use the configurable v2 engine at the repository root.")
    raise SystemExit(main())
