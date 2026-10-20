#!/usr/bin/env python3
"""Import exactly five frozen EML files into one verified Gmail account.

The script defaults to an offline preflight. A write requires both --execute and
an exact --confirm-destination value. OAuth tokens are kept only in memory.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import sys
from contextlib import contextmanager
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaFileUpload


SCOPES = (
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/gmail.insert",
)
PILOT_SIZE = 5


class PreflightError(RuntimeError):
    """Raised when a safety check fails before an API write."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


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
        raise PreflightError(f"Cannot read valid JSON from {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise PreflightError(f"Expected a JSON object in {path}")
    return value


def write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def validate_credentials(path: Path, expected_client_id: str) -> None:
    data = load_json(path)
    installed = data.get("installed")
    if not isinstance(installed, dict):
        raise PreflightError("OAuth JSON must be a Desktop app client ('installed').")
    actual_client_id = str(installed.get("client_id", ""))
    if actual_client_id != expected_client_id:
        raise PreflightError(
            "OAuth client mismatch: the credentials are not the frozen pilot client."
        )


def parse_message_identity(path: Path, mailbox: str) -> tuple[str, str, int]:
    try:
        message = BytesParser(policy=policy.default).parsebytes(path.read_bytes())
    except OSError as exc:
        raise PreflightError(f"Cannot read pilot file {path}: {exc}") from exc
    if message.defects:
        defect_names = ", ".join(type(item).__name__ for item in message.defects)
        raise PreflightError(f"Pilot file {path.name} has parser defects: {defect_names}")
    message_id = str(message.get("Message-ID", "")).strip()
    date_header = str(message.get("Date", "")).strip()
    if not message_id or not date_header:
        raise PreflightError(f"Pilot file {path.name} lacks Message-ID or Date.")
    try:
        parsed_date = parsedate_to_datetime(date_header)
    except (TypeError, ValueError, OverflowError) as exc:
        raise PreflightError(f"Pilot file {path.name} has an invalid Date header.") from exc
    if parsed_date.tzinfo is None:
        raise PreflightError(f"Pilot file {path.name} has a Date without a timezone.")
    for header_name in ("Delivered-To", "To"):
        addresses = {
            address.strip().lower()
            for _, address in getaddresses(message.get_all(header_name, []))
        }
        if mailbox not in addresses:
            raise PreflightError(
                f"Pilot file {path.name} does not name {mailbox} in {header_name}."
            )
    return message_id, date_header, int(parsed_date.timestamp() * 1000)


def validate_manifest(
    manifest: dict[str, Any], credentials_path: Path
) -> tuple[str, Path, list[dict[str, Any]]]:
    destination = str(manifest.get("expected_destination", "")).strip().lower()
    source_mailbox = str(manifest.get("source_mailbox", "")).strip().lower()
    if not all(re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", address) for address in (destination, source_mailbox)):
        raise PreflightError("The frozen manifest must identify source and destination email addresses.")

    if manifest.get("planned_count") != PILOT_SIZE:
        raise PreflightError(f"Manifest planned_count must be exactly {PILOT_SIZE}.")
    rows = manifest.get("messages")
    if not isinstance(rows, list) or len(rows) != PILOT_SIZE:
        raise PreflightError(f"Manifest must contain exactly {PILOT_SIZE} messages.")

    root = Path(str(manifest.get("source_root", ""))).expanduser().resolve()
    expected_folder = str(manifest.get("expected_source_folder", ""))
    if not root.is_dir() or root.name != expected_folder:
        raise PreflightError("The selected source folder is not the frozen Cafe24 Inbox export.")

    all_eml = list(root.glob("*.eml"))
    expected_files = int(manifest.get("source_eml_count", -1))
    expected_bytes = int(manifest.get("source_total_bytes", -1))
    actual_bytes = sum(path.stat().st_size for path in all_eml)
    if len(all_eml) != expected_files or actual_bytes != expected_bytes:
        raise PreflightError(
            "The Cafe24 source export changed: file count or total bytes no longer match."
        )

    seen_ids: set[str] = set()
    seen_paths: set[str] = set()
    seen_pilot_ids: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise PreflightError("Each manifest message must be a JSON object.")
        pilot_id = str(row.get("pilot_id", ""))
        if not pilot_id or pilot_id in seen_pilot_ids:
            raise PreflightError("Every pilot_id must be present and unique.")
        seen_pilot_ids.add(pilot_id)
        relative = str(row.get("relative_path", ""))
        candidate = (root / relative).resolve()
        try:
            candidate.relative_to(root)
        except ValueError as exc:
            raise PreflightError("A pilot path escapes the frozen source folder.") from exc
        if not candidate.is_file() or candidate.suffix.lower() != ".eml":
            raise PreflightError(f"Pilot source file is missing: {relative}")
        if relative in seen_paths:
            raise PreflightError(f"Duplicate pilot path: {relative}")
        seen_paths.add(relative)

        size = candidate.stat().st_size
        digest = sha256_file(candidate)
        if size != int(row.get("size_bytes", -1)) or digest != row.get("sha256"):
            raise PreflightError(f"Pilot source file changed: {relative}")

        message_id, date_header, internal_date_ms = parse_message_identity(
            candidate, source_mailbox
        )
        if message_id != row.get("rfc822_message_id") or date_header != row.get("date_header"):
            raise PreflightError(f"Pilot message identity changed: {relative}")
        if internal_date_ms != int(row.get("expected_internal_date_ms", -1)):
            raise PreflightError(f"Pilot message date changed: {relative}")
        if message_id in seen_ids:
            raise PreflightError("The five-message pilot contains a repeated Message-ID.")
        seen_ids.add(message_id)

        if row.get("gmail_label_ids") != ["INBOX"]:
            raise PreflightError("Every pilot message must be imported only with the INBOX label.")

    expected_client_id = str(manifest.get("oauth_client_id", ""))
    validate_credentials(credentials_path, expected_client_id)
    return destination, root, rows


def granted_scopes(flow: InstalledAppFlow) -> set[str]:
    value = flow.oauth2session.token.get("scope", ())
    if isinstance(value, str):
        return set(value.split())
    return {str(item) for item in value}


def authorize(credentials_path: Path, expected_email: str):
    flow = InstalledAppFlow.from_client_secrets_file(
        str(credentials_path), scopes=SCOPES
    )
    flow.run_local_server(
        port=0,
        open_browser=True,
        prompt="select_account",
        login_hint=expected_email,
        access_type="online",
        authorization_prompt_message="AUTH_URL: {url}",
        success_message=(
            "OAuth finished. Return to Terminal; the script will verify the exact "
            "account before importing the five pilot messages."
        ),
    )
    if not set(SCOPES).issubset(granted_scopes(flow)):
        raise PreflightError("Google did not grant all required pilot scopes.")

    request = Request(
        "https://openidconnect.googleapis.com/v1/userinfo",
        headers={"Authorization": "Bearer " + flow.credentials.token},
    )
    try:
        with urlopen(request, timeout=15) as response:
            user = json.load(response)
    except Exception as exc:
        raise PreflightError("Could not verify the authorized Google account.") from exc
    actual = str(user.get("email", "")).strip().lower()
    if actual != expected_email:
        raise PreflightError(
            f"Authorized account is {actual or '(unavailable)'}, expected {expected_email}; "
            "nothing was imported."
        )
    return flow.credentials


def new_checkpoint(destination: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "destination": destination,
        "created_at": utc_now(),
        "updated_at": utc_now(),
        "messages": {
            str(row["pilot_id"]): {
                "status": "pending",
                "rfc822_message_id": row["rfc822_message_id"],
            }
            for row in rows
        },
    }


def load_checkpoint(
    path: Path, destination: str, rows: list[dict[str, Any]]
) -> dict[str, Any]:
    if not path.exists():
        return new_checkpoint(destination, rows)
    checkpoint = load_json(path)
    if checkpoint.get("destination") != destination:
        raise PreflightError("Checkpoint destination does not match the pilot destination.")
    states = checkpoint.get("messages")
    if not isinstance(states, dict) or set(states) != {
        str(row["pilot_id"]) for row in rows
    }:
        raise PreflightError("Checkpoint does not match the frozen five-message manifest.")
    for row in rows:
        state = states[str(row["pilot_id"])]
        if state.get("rfc822_message_id") != row["rfc822_message_id"]:
            raise PreflightError("Checkpoint Message-ID does not match the manifest.")
        status = state.get("status")
        if status in {"inflight", "uncertain", "failed", "review_required"}:
            raise PreflightError(
                f"Checkpoint has {row['pilot_id']} status={status}; stop and reconcile it "
                "in Gmail before any retry."
            )
        if status not in {
            "pending",
            "succeeded",
            "imported_pending_verification",
            "verified",
        }:
            raise PreflightError(f"Unknown checkpoint status for {row['pilot_id']}.")
    return checkpoint


def save_state(
    checkpoint_path: Path,
    checkpoint: dict[str, Any],
    pilot_id: str,
    **updates: Any,
) -> None:
    checkpoint["messages"][pilot_id].update(updates)
    checkpoint["updated_at"] = utc_now()
    write_json_atomic(checkpoint_path, checkpoint)


@contextmanager
def exclusive_checkpoint_lock(checkpoint_path: Path):
    """Prevent concurrent pilot processes from sharing one pending checkpoint."""
    lock_path = checkpoint_path.with_name(checkpoint_path.name + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+", encoding="utf-8") as handle:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise PreflightError(
                "Another pilot process is running with this checkpoint."
            ) from exc
        handle.seek(0)
        handle.truncate()
        handle.write(f"pid={os.getpid()} locked_at={utc_now()}\n")
        handle.flush()
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def import_pilot(
    credentials,
    root: Path,
    rows: list[dict[str, Any]],
    checkpoint_path: Path,
    checkpoint: dict[str, Any],
) -> int:
    service = build("gmail", "v1", credentials=credentials, cache_discovery=False)
    imported_this_run = 0
    for row in rows:
        pilot_id = str(row["pilot_id"])
        state = checkpoint["messages"][pilot_id]
        if state["status"] in {
            "succeeded",
            "imported_pending_verification",
            "verified",
        }:
            print(f"{pilot_id}: already imported; skipped")
            continue

        source_path = root / str(row["relative_path"])
        if sha256_file(source_path) != row["sha256"]:
            raise PreflightError(f"Pilot source changed immediately before {pilot_id}.")

        save_state(
            checkpoint_path,
            checkpoint,
            pilot_id,
            status="inflight",
            attempted_at=utc_now(),
        )
        try:
            media = MediaFileUpload(
                str(source_path), mimetype="message/rfc822", resumable=False
            )
            result = (
                service.users()
                .messages()
                .import_(
                    userId="me",
                    body={"labelIds": ["INBOX"]},
                    media_body=media,
                    internalDateSource="dateHeader",
                    neverMarkSpam=True,
                    processForCalendar=False,
                    deleted=False,
                    fields="id,threadId,labelIds,internalDate",
                )
                .execute(num_retries=0)
            )
        except HttpError as exc:
            status_code = int(getattr(exc.resp, "status", 0) or 0)
            final_status = "failed" if 400 <= status_code < 500 else "uncertain"
            reason = exc._get_reason() if hasattr(exc, "_get_reason") else "API error"
            save_state(
                checkpoint_path,
                checkpoint,
                pilot_id,
                status=final_status,
                http_status=status_code,
                error=str(reason)[:500],
            )
            print(
                f"{pilot_id}: {final_status} (HTTP {status_code}); stopped to prevent a duplicate.",
                file=sys.stderr,
            )
            return 4
        except Exception as exc:
            save_state(
                checkpoint_path,
                checkpoint,
                pilot_id,
                status="uncertain",
                error_type=type(exc).__name__,
            )
            print(
                f"{pilot_id}: uncertain after {type(exc).__name__}; stopped to prevent a duplicate.",
                file=sys.stderr,
            )
            return 4

        gmail_id = str(result.get("id", ""))
        if not gmail_id:
            save_state(
                checkpoint_path,
                checkpoint,
                pilot_id,
                status="uncertain",
                error="API response lacked a Gmail message ID",
            )
            print(f"{pilot_id}: uncertain response; stopped.", file=sys.stderr)
            return 4
        returned_labels = result.get("labelIds")
        returned_internal_date_value = result.get("internalDate")
        returned_internal_date = (
            str(returned_internal_date_value)
            if returned_internal_date_value is not None
            else None
        )
        response_issues = []
        if returned_labels is not None and "INBOX" not in returned_labels:
            response_issues.append("API explicitly returned labels without INBOX")
        if (
            returned_internal_date is not None
            and returned_internal_date != str(row["expected_internal_date_ms"])
        ):
            response_issues.append("API internalDate did not match the source Date header")
        if response_issues:
            save_state(
                checkpoint_path,
                checkpoint,
                pilot_id,
                status="review_required",
                gmail_message_id=gmail_id,
                gmail_thread_id=str(result.get("threadId", "")),
                returned_label_ids=returned_labels,
                returned_internal_date=returned_internal_date,
                issues=response_issues,
            )
            print(
                f"{pilot_id}: imported but requires review; stopped before the next message.",
                file=sys.stderr,
            )
            return 4
        omitted_response_fields = [
            field
            for field, value in (
                ("threadId", result.get("threadId")),
                ("labelIds", returned_labels),
                ("internalDate", returned_internal_date),
            )
            if value is None
        ]
        save_state(
            checkpoint_path,
            checkpoint,
            pilot_id,
            status="imported_pending_verification",
            imported_at=utc_now(),
            gmail_message_id=gmail_id,
            gmail_thread_id=str(result.get("threadId", "")),
            returned_label_ids=returned_labels if returned_labels is not None else [],
            returned_internal_date=returned_internal_date or "",
            omitted_response_fields=omitted_response_fields,
            manual_verification_required=True,
        )
        imported_this_run += 1
        print(f"{pilot_id}: imported; Gmail message ID {gmail_id}")

    imported = sum(
        1
        for state in checkpoint["messages"].values()
        if state.get("status")
        in {"succeeded", "imported_pending_verification", "verified"}
    )
    verification_pending = sum(
        1
        for state in checkpoint["messages"].values()
        if state.get("status") == "imported_pending_verification"
    )
    print("authorized_destination:", checkpoint["destination"])
    print("pilot_imported_total:", imported)
    print("imported_this_run:", imported_this_run)
    print("manual_verification_pending:", verification_pending)
    return 0 if imported == PILOT_SIZE else 5


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--credentials", type=Path, required=True)
    parser.add_argument("--checkpoint", type=Path, required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--confirm-destination")
    parser.add_argument("--confirm-no-existing-copies", action="store_true")
    parser.add_argument(
        "--confirm-pending-have-no-existing-copies", action="store_true"
    )
    args = parser.parse_args()

    try:
        manifest = load_json(args.manifest)
        destination, root, rows = validate_manifest(manifest, args.credentials)
        print("source_mailbox:", manifest["source_mailbox"])
        print("source_export:", root)
        print("source_eml_count:", manifest["source_eml_count"])
        print("destination_mailbox:", destination)
        print("pilot_messages:", len(rows))
        if not args.execute:
            print("preflight: PASS")
            print("api_writes_this_run: 0")
            return 0
        if (args.confirm_destination or "").strip().lower() != destination:
            raise PreflightError(
                f"Execution requires --confirm-destination {destination}."
            )
        expected_checkpoint = Path(str(manifest.get("expected_checkpoint", ""))).resolve()
        if args.checkpoint.resolve() != expected_checkpoint:
            raise PreflightError("Checkpoint path is not the frozen pilot checkpoint.")
        with exclusive_checkpoint_lock(args.checkpoint):
            checkpoint_already_existed = args.checkpoint.exists()
            checkpoint = load_checkpoint(args.checkpoint, destination, rows)
            if checkpoint_already_existed:
                if not args.confirm_pending_have_no_existing_copies:
                    raise PreflightError(
                        "Confirm every still-pending Message-ID has zero Gmail results, "
                        "then add --confirm-pending-have-no-existing-copies."
                    )
            elif not (
                args.confirm_no_existing_copies
                or args.confirm_pending_have_no_existing_copies
            ):
                raise PreflightError(
                    "First run all five Gmail searches and confirm they return zero results; "
                    "then add --confirm-no-existing-copies."
                )
            write_json_atomic(args.checkpoint, checkpoint)
            credentials = authorize(args.credentials, destination)
            print("authorized_email:", destination)
            print("exact_account_match: true")
            return import_pilot(credentials, root, rows, args.checkpoint, checkpoint)
    except PreflightError as exc:
        print(f"STOPPED: {exc}", file=sys.stderr)
        print("No further messages were imported by this run.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
