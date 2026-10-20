# Sanitized historical reference: source-specific evidence and live configuration are not distributed.
#!/usr/bin/env python3
"""Own one import process and its read-only final verifier; never auto-retry writes.

Launch with the migration's OAuth-capable Python interpreter:
    python finish_when_done.py --run-import
Or verify an already-completed import:
    python finish_when_done.py --verify-only
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys

import runner


m = runner.engine
BASE = Path(__file__).resolve().parent
MAILBOX = 'example-49d20801@example.org'
SOURCE_COUNT = 951


def save(status):
    status["updated_at"] = m.utc_now()
    m.write_json_atomic(BASE / "completion-status.json", status)


@contextmanager
def supervisor_lock():
    with (BASE / "completion-supervisor.lock").open("a+") as handle:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise m.MigrationError("Completion supervisor is already active.") from exc
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def check_pilot(profile):
    pilot = m.load_json(BASE / "pilot-content-verification.json")
    manifest = m.load_manifest(profile)
    checkpoint = m.load_checkpoint(profile, manifest, create=False)
    rows = pilot.get("rows", [])
    if (pilot.get("ok") is not True or pilot.get("destination") != MAILBOX
            or pilot.get("checked_count") != 5 or pilot.get("passed_count") != 5
            or len(rows) != 5 or len({row.get("gmail_message_id") for row in rows}) != 5):
        raise m.MigrationError("Five-receipt pilot verification has not passed.")
    for row in rows:
        state = checkpoint["states"].get(row.get("item_key"), {})
        if (row.get("ok") is not True or state.get("status") != "verified"
                or state.get("gmail_message_id") != row.get("gmail_message_id")
                or state.get("verified_prepared_sha256") != row.get("prepared_sha256")):
            raise m.MigrationError("Pilot evidence no longer matches the checkpoint.")


def launch_once(command, log_path, status, phase, pid_key):
    environment = os.environ.copy()
    environment.pop('RFC822_PILOT_LIMIT', None)
    with log_path.open("ab", buffering=0) as log:
        child = subprocess.Popen(command, cwd=BASE, env=environment,
                                 stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
        status.update({"phase": phase, pid_key: child.pid, "last_command": command})
        save(status)
        return child.wait()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--run-import", action="store_true")
    mode.add_argument("--verify-only", action="store_true")
    args = parser.parse_args(argv)
    os.umask(0o077)
    status = {"destination": MAILBOX, "source_count": SOURCE_COUNT,
              "supervisor_pid": os.getpid(), "started_at": m.utc_now(),
              "automatic_write_retries": 0, "phase": "preflight"}
    # A second supervisor must not overwrite the active owner's status file.
    try:
        with supervisor_lock():
            try:
                profile = m.load_profile(BASE / "profile.json")
                runner.guard_profile(profile)
                if args.run_import:
                    check_pilot(profile)
                    code = launch_once([
                        sys.executable, str(BASE / "runner.py"), "run", "--profile", str(profile.path),
                        "--confirm-destination", MAILBOX, "--confirm-source-count", str(SOURCE_COUNT),
                        "--continue-known-security-rejections-local-only",
                    ], BASE / "run.log", status, "importing", "import_pid")
                    status["import_return_code"] = code
                    if code != 0:
                        status.update({"phase": "needs_review", "exit_code": code,
                                       "detail": "Import stopped. Inspect checkpoint and run.log; no automatic write retry."})
                        save(status)
                        return code
                final = m.load_json(profile.report_path)
                if final.get("complete") is not True:
                    raise m.MigrationError("Import report is not complete; final Gmail verifier was not started.")
                code = launch_once([sys.executable, str(BASE / "verify_final.py")],
                                   BASE / "final-verification.log", status, "verifying", "verification_pid")
                status["verification_return_code"] = code
                verification = m.load_json(BASE / "final-verification.json")
                status.update({"exit_code": code, "result": str(BASE / "RUN_RESULT.md"),
                               "accounted_complete": verification.get("accounted_complete", False),
                               "gmail_complete": verification.get("gmail_complete", False),
                               "local_only_reviewed": verification.get("local_only_reviewed"),
                               "phase": ("verified" if verification.get("gmail_complete") else "verified_with_local_only")
                                        if code == 0 and verification.get("ok") is True else "verification_needs_review"})
                if verification.get("ok") is not True:
                    status["exit_code"] = code or 1
                save(status)
                return status["exit_code"]
            except Exception as exc:
                status.update({"phase": "needs_review", "error_type": type(exc).__name__, "exit_code": 2})
                save(status)
                return 2
    except m.MigrationError:
        print("STOPPED: another completion supervisor is active.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit("Archived reference variant. Use the configurable v2 engine at the repository root.")
    raise SystemExit(main())
