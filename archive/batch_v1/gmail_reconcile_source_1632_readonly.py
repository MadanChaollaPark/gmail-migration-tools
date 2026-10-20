# Sanitized historical reference: source-specific evidence and live configuration are not distributed.
#!/usr/bin/env python3
'Read-only Gmail reconciliation for interrupted mailbox source 1632.'

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
import time
from datetime import datetime, timezone
from email import policy
from email.header import decode_header, make_header
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build


SCOPES = (
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/gmail.readonly",
)
SOURCE_ID = 1632
EXPECTED_EMAIL = 'example-b54b38f4@example.org'
EXPECTED_CLIENT_ID = (
    'example-client.apps.googleusercontent.com'
)
EXPECTED_SOURCE_SHA256 = (
    '000000000000000000000000000000000000000000000000000000000000dfb7'
)
EXPECTED_MESSAGE_ID = '<example-34730551@example.org>'
METADATA_HEADERS = ("Message-ID", "Subject", "Date", "From", "To")
ZERO_MATCH_RECHECK_SECONDS = 30
NETWORK_RETRY_DELAYS_SECONDS = (1, 2, 4)
GOOGLE_API_NUM_RETRIES = 3


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        prefix=path.name + ".", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def header_map(message: dict[str, Any]) -> dict[str, str]:
    headers = message.get("payload", {}).get("headers", [])
    return {
        str(header.get("name", "")).lower(): str(header.get("value", ""))
        for header in headers
    }


def normalized_header(value: str) -> str:
    try:
        decoded = str(make_header(decode_header(value)))
    except (LookupError, UnicodeError):
        decoded = value
    return " ".join(decoded.split())


def rfc2822_date_semantics(value: str) -> dict[str, int] | None:
    """Normalize an RFC 2822 date by instant and its stated UTC offset."""
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if parsed is None or parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return {
        "timestamp_ms": int(parsed.timestamp() * 1000),
        "utc_offset_seconds": int(parsed.utcoffset().total_seconds()),
    }


def fetch_userinfo(access_token: str) -> dict[str, Any]:
    """Fetch exact-account evidence with bounded transient-network retries."""
    request = Request(
        "https://openidconnect.googleapis.com/v1/userinfo",
        headers={"Authorization": "Bearer " + access_token},
    )
    attempts = len(NETWORK_RETRY_DELAYS_SECONDS) + 1
    for attempt in range(attempts):
        try:
            with urlopen(request, timeout=15) as response:
                return json.load(response)
        except HTTPError as exc:
            retryable = exc.code == 429 or 500 <= exc.code <= 599
            if not retryable or attempt == attempts - 1:
                raise
        except (URLError, TimeoutError, ConnectionError, OSError):
            if attempt == attempts - 1:
                raise
        delay = NETWORK_RETRY_DELAYS_SECONDS[attempt]
        print(
            f"userinfo_retry: transient network failure; retrying in {delay}s",
            flush=True,
        )
        time.sleep(delay)
    raise AssertionError("userinfo retry loop exhausted unexpectedly")


def search_pass(service: Any, queries: tuple[str, ...]) -> dict[str, Any]:
    listed_by_id: dict[str, dict[str, str]] = {}
    query_receipts: list[dict[str, Any]] = []
    for query in queries:
        page_token: str | None = None
        pages_checked = 0
        result_size_estimate = 0
        query_ids: list[str] = []
        while True:
            list_kwargs: dict[str, Any] = {
                "userId": "me",
                "q": query,
                "includeSpamTrash": True,
                "maxResults": 500,
                "fields": "messages(id,threadId),nextPageToken,resultSizeEstimate",
            }
            if page_token:
                list_kwargs["pageToken"] = page_token
            result = (
                service.users()
                .messages()
                .list(**list_kwargs)
                .execute(num_retries=GOOGLE_API_NUM_RETRIES)
            )
            pages_checked += 1
            result_size_estimate = max(
                result_size_estimate, int(result.get("resultSizeEstimate", 0))
            )
            for listed_message in result.get("messages", []):
                gmail_id = str(listed_message.get("id", ""))
                if gmail_id:
                    listed_by_id[gmail_id] = listed_message
                    query_ids.append(gmail_id)
            page_token = str(result.get("nextPageToken", ""))
            if not page_token:
                break
        query_receipts.append(
            {
                "query": query,
                "pages_checked": pages_checked,
                "result_size_estimate": result_size_estimate,
                "listed_gmail_message_ids": sorted(set(query_ids)),
                "all_pages_exhausted": True,
            }
        )

    candidates: list[dict[str, Any]] = []
    for listed_message in listed_by_id.values():
        metadata = (
            service.users()
            .messages()
            .get(
                userId="me",
                id=listed_message["id"],
                format="metadata",
                metadataHeaders=list(METADATA_HEADERS),
                fields="id,threadId,labelIds,internalDate,sizeEstimate,payload(headers)",
            )
            .execute(num_retries=GOOGLE_API_NUM_RETRIES)
        )
        headers = header_map(metadata)
        candidates.append(
            {
                "gmail_message_id": str(metadata.get("id", "")),
                "thread_id": str(metadata.get("threadId", "")),
                "label_ids": list(metadata.get("labelIds", [])),
                "internal_date_ms": str(metadata.get("internalDate", "")),
                "size_estimate": int(metadata.get("sizeEstimate", 0)),
                "headers": {
                    name: headers.get(name.lower(), "") for name in METADATA_HEADERS
                },
                "exact_message_id_match": (
                    headers.get("message-id", "").strip() == EXPECTED_MESSAGE_ID
                ),
            }
        )
    candidates.sort(key=lambda candidate: candidate["gmail_message_id"])
    return {
        "checked_at": utc_now(),
        "query_receipts": query_receipts,
        "listed_result_count": len(listed_by_id),
        "candidates": candidates,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--credentials", type=Path, required=True)
    parser.add_argument("--expected-email", required=True)
    parser.add_argument("--source-eml", type=Path, required=True)
    parser.add_argument("--evidence-out", type=Path, required=True)
    args = parser.parse_args()

    client = json.loads(args.credentials.read_text(encoding="utf-8"))
    if "installed" not in client:
        parser.error("OAuth JSON must be a Desktop app client (installed).")
    if str(client["installed"].get("client_id", "")) != EXPECTED_CLIENT_ID:
        parser.error("OAuth JSON client ID does not match the audited desktop client.")

    source_bytes = args.source_eml.read_bytes()
    source = BytesParser(policy=policy.default).parsebytes(
        source_bytes, headersonly=True
    )
    source_sha256 = sha256_bytes(source_bytes)
    if source_sha256 != EXPECTED_SOURCE_SHA256:
        parser.error("Source 1632 SHA-256 no longer matches the audited EML.")
    source_headers = {name: str(source.get(name, "")) for name in METADATA_HEADERS}
    if source_headers["Message-ID"].strip() != EXPECTED_MESSAGE_ID:
        parser.error("Source 1632 Message-ID no longer matches the audited value.")
    source_internal_date_ms = str(
        int(parsedate_to_datetime(source_headers["Date"]).timestamp() * 1000)
    )
    source_date_semantics = rfc2822_date_semantics(source_headers["Date"])
    if source_date_semantics is None:
        parser.error("Source 1632 Date header is not an aware RFC 2822 date.")

    expected_email = args.expected_email.strip().lower()
    if expected_email != EXPECTED_EMAIL:
        parser.error(f"Expected email must be exactly {EXPECTED_EMAIL}.")
    flow = InstalledAppFlow.from_client_secrets_file(
        str(args.credentials), scopes=SCOPES
    )
    flow.run_local_server(
        port=0,
        open_browser=False,
        prompt="select_account",
        login_hint=expected_email,
        access_type="online",
        authorization_prompt_message="AUTH_URL: {url}",
        success_message=(
            "Read-only Gmail reconciliation finished. No email was changed. "
            "You may close this tab."
        ),
    )

    granted_value = flow.oauth2session.token.get("scope", ())
    granted = (
        set(granted_value.split())
        if isinstance(granted_value, str)
        else set(granted_value)
    )
    if not set(SCOPES).issubset(granted):
        raise SystemExit("Required read-only scopes were not granted.")

    user = fetch_userinfo(flow.credentials.token)
    authorized_email = str(user.get("email", "")).strip().lower()
    if authorized_email != expected_email:
        raise SystemExit(
            f"Wrong Google account authorized: {authorized_email or '(unavailable)'}"
        )

    service = build("gmail", "v1", credentials=flow.credentials, cache_discovery=False)
    bare_message_id = EXPECTED_MESSAGE_ID.removeprefix("<").removesuffix(">")
    queries = (
        f"in:anywhere rfc822msgid:{EXPECTED_MESSAGE_ID}",
        f"in:anywhere rfc822msgid:{bare_message_id}",
    )
    passes = [search_pass(service, queries)]
    first_exact = [
        candidate
        for candidate in passes[0]["candidates"]
        if candidate["exact_message_id_match"]
    ]
    if not first_exact:
        time.sleep(ZERO_MATCH_RECHECK_SECONDS)
        passes.append(search_pass(service, queries))

    candidates_by_id: dict[str, dict[str, Any]] = {}
    for search_receipt in passes:
        for candidate in search_receipt["candidates"]:
            candidates_by_id[candidate["gmail_message_id"]] = candidate
    candidates = sorted(
        candidates_by_id.values(), key=lambda candidate: candidate["gmail_message_id"]
    )
    for candidate in candidates:
        text_header_matches = {
            name: (
                normalized_header(candidate["headers"].get(name, ""))
                == normalized_header(source_headers[name])
            )
            for name in ("Subject", "From", "To")
        }
        candidate_date_semantics = rfc2822_date_semantics(
            candidate["headers"].get("Date", "")
        )
        date_header_matches = candidate_date_semantics == source_date_semantics
        candidate["header_matches"] = {
            "Message-ID": candidate["exact_message_id_match"],
            "Subject": text_header_matches["Subject"],
            "Date": date_header_matches,
            "From": text_header_matches["From"],
            "To": text_header_matches["To"],
        }
        candidate["date_header_semantics"] = candidate_date_semantics
        candidate["core_headers_match"] = (
            all(text_header_matches.values()) and date_header_matches
        )
        candidate["inbox_label_present"] = "INBOX" in candidate["label_ids"]
        candidate["internal_date_matches_source_date"] = (
            candidate["internal_date_ms"] == source_internal_date_ms
        )
    message_id_matches = [
        candidate for candidate in candidates if candidate["exact_message_id_match"]
    ]
    exact = [
        candidate
        for candidate in candidates
        if candidate["exact_message_id_match"]
        and candidate["core_headers_match"]
        and candidate["inbox_label_present"]
        and candidate["internal_date_matches_source_date"]
    ]
    evidence = {
        "schema_version": 1,
        "purpose": "reconcile interrupted Gmail API response for source 1632",
        "checked_at": utc_now(),
        "source_id": SOURCE_ID,
        "source_eml": str(args.source_eml),
        "source_sha256": source_sha256,
        "source_headers": source_headers,
        "source_date_semantics": source_date_semantics,
        "source_internal_date_ms": source_internal_date_ms,
        "expected_destination": expected_email,
        "authorized_email": authorized_email,
        "exact_account_match": True,
        "oauth_client_id": EXPECTED_CLIENT_ID,
        "requested_oauth_scopes": list(SCOPES),
        "granted_oauth_scopes": sorted(granted),
        "queries": list(queries),
        "include_spam_trash": True,
        "zero_match_recheck_seconds": (
            ZERO_MATCH_RECHECK_SECONDS if len(passes) == 2 else 0
        ),
        "search_passes": passes,
        "all_queries_exhausted": True,
        "listed_result_count": len(candidates),
        "message_id_match_count": len(message_id_matches),
        "exact_match_count": len(exact),
        "candidates": candidates,
        "gmail_mutations": 0,
        "token_persisted": False,
    }
    write_json_atomic(args.evidence_out, evidence)

    print("authorized_email:", authorized_email)
    print("exact_account_match: true")
    print("search_passes:", len(passes))
    print("listed_result_count:", len(candidates))
    print("message_id_match_count:", len(message_id_matches))
    print("exact_match_count:", len(exact))
    if len(exact) == 1:
        print("matched_gmail_message_id:", exact[0]["gmail_message_id"])
    print("evidence:", args.evidence_out)
    print("gmail_writes_this_run: 0")
    print("token_persisted: false")
    unambiguous = len(message_id_matches) == len(exact) and len(exact) <= 1
    return 0 if unambiguous else 4


if __name__ == "__main__":
    raise SystemExit("Archived reference variant. Use the configurable v2 engine at the repository root.")
    raise SystemExit(main())
