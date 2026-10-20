# Sanitized historical reference: source-specific evidence and live configuration are not distributed.
#!/usr/bin/env python3
'Validate and import the mailbox Cafe24 Inbox archive in bounded batches.'

from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import json
import os
import sys
import tempfile
from copy import deepcopy
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

from google.auth.credentials import AnonymousCredentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaFileUpload

from legacy_common import (
    DATE_UTC_NORMALIZATION_IDS,
    DESTINATION,
    DUPLICATE_SKIP_TO_KEEP,
    OAUTH_CLIENT_ID,
    SOURCE_BYTES,
    SOURCE_COUNT,
    SOURCE_FOLDER,
    SOURCE_ROOT,
    ArchiveError,
    archive_files,
    normalize_eml,
    prepared_record,
    sha256_bytes,
)


PROJECT_ROOT = Path('/private/migration-example/how-x20-2')
CANONICAL_MANIFEST = PROJECT_ROOT / 'work/mailbox-gmail-full/manifest.json'
CANONICAL_CHECKPOINT = PROJECT_ROOT / 'work/mailbox-gmail-full/checkpoint.json'
PILOT_MANIFEST = PROJECT_ROOT / 'work/mailbox-gmail-pilot/manifest.json'
PILOT_CHECKPOINT = PROJECT_ROOT / 'work/mailbox-gmail-pilot/checkpoint.json'
SECURITY_EXCLUSIONS = (
    PROJECT_ROOT / 'work/mailbox-gmail-full/security-attachment-exclusions.json'
)
HTML_PHISHING_EXCLUSIONS = (
    PROJECT_ROOT / 'work/mailbox-gmail-full/security-html-phishing-exclusions.json'
)
HTML_REDIRECT_EXCLUSIONS = (
    PROJECT_ROOT / 'work/mailbox-gmail-full/security-html-redirect-exclusions.json'
)
BODY_PHISHING_EXCLUSIONS = (
    PROJECT_ROOT / 'work/mailbox-gmail-full/security-body-phishing-exclusions.json'
)
GMAIL_REJECTED_ATTACHMENT_EXCLUSIONS = (
    PROJECT_ROOT
    / 'work/mailbox-gmail-full/gmail-rejected-attachment-exclusions.json'
)
LAST_BATCH_SEARCHES = PROJECT_ROOT / 'outputs/mailbox_full_last_batch_searches.txt'
SCOPES = (
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/gmail.insert",
)
MAX_BATCH_SIZE = 250
EXPECTED_NEW_IMPORTS = 1997
EXPECTED_TARGET_TOTAL = 2002
SECURITY_EXCLUSION_COUNT = 20
EFFECTIVE_NEW_IMPORTS = 1977
EFFECTIVE_TARGET_TOTAL = 1982
SECURITY_EXCLUSION_IDS = {
    65,
    89,
    128,
    129,
    133,
    137,
    168,
    175,
    317,
    318,
    329,
    1042,
    1188,
    1264,
    1345,
    1478,
    1493,
    1585,
    1813,
    1984,
}
SECURITY_EXCLUSIONS_SHA256 = (
    '000000000000000000000000000000000000000000000000000000000000d6a3'
)
SOURCE_65_ATTEMPTED_AT = "2026-09-17T05:16:15+00:00"
SOURCE_65_ERROR = (
    "Invalid attachment. Please check https://support.google.com/mail/answer/6590."
)
HTML_PHISHING_EXCLUSION_COUNT = 14
HTML_PHISHING_EXCLUSION_IDS = {
    74,
    76,
    146,
    147,
    188,
    333,
    347,
    469,
    1015,
    1022,
    1479,
    1480,
    1966,
    1976,
}
HTML_PHISHING_EXCLUSIONS_SHA256 = (
    '0000000000000000000000000000000000000000000000000000000000004aee'
)
TOTAL_SECURITY_EXCLUSION_COUNT = 34
SAFE_NEW_IMPORTS_AFTER_HTML_EXCLUSIONS = 1963
SAFE_TARGET_TOTAL_AFTER_HTML_EXCLUSIONS = 1968
HTML_REDIRECT_EXCLUSION_COUNT = 4
HTML_REDIRECT_EXCLUSION_IDS = {1052, 1063, 1199, 1458}
HTML_REDIRECT_EXCLUSIONS_SHA256 = (
    '0000000000000000000000000000000000000000000000000000000000008aa3'
)
FINAL_SECURITY_EXCLUSION_COUNT = 38
FINAL_SAFE_NEW_IMPORTS = 1959
FINAL_SAFE_TARGET_TOTAL = 1964
BODY_PHISHING_EXCLUSION_IDS = {
    103,
    112,
    124,
    134,
    159,
    162,
    170,
    177,
    189,
    271,
    281,
    288,
    304,
    320,
    334,
    369,
    389,
    391,
    396,
    433,
    449,
    456,
    468,
    528,
    533,
    600,
    913,
    1003,
    1025,
    1026,
    1046,
    1059,
    1067,
    1093,
    1095,
    1159,
    1263,
    1333,
    1368,
    1379,
    1457,
    1483,
    1612,
    1866,
    1867,
    1868,
    1879,
    1963,
    1965,
    1969,
    1970,
    1972,
    1973,
    1974,
    1977,
    1978,
    1986,
    1993,
    1994,
    1995,
    1998,
    2005,
}
BODY_PHISHING_EXCLUSION_COUNT = len(BODY_PHISHING_EXCLUSION_IDS)
BODY_PHISHING_CLASSIFICATIONS = {
    "cafe24_payment_phishing",
    "copyright_enforcement_phishing",
    "crypto_wallet_credential_phishing",
    "fake_buykorea_business_inquiry",
    "fake_contract_order_document",
    "fake_design_document",
    "fake_domain_invoice",
    "fake_docusign_document",
    "fake_hosting_invoice",
    "fake_hr_bonus_document",
    "fake_hr_payroll_document",
    "fake_hr_shared_document",
    "fake_invoice_document",
    "fake_invoice_remittance_document",
    "fake_kotra_trade_document",
    "fake_purchase_order_document",
    "fake_remittance_document",
    "fake_shipping_document",
    "fake_tax_invoice_document",
    "fake_tt_payment_document",
    "linkedin_document_phishing",
    "mailbox_credential_phishing",
    "meta_account_phishing",
}
BODY_PHISHING_EXCLUSIONS_SHA256 = (
    '0000000000000000000000000000000000000000000000000000000000009d6d'
)
COMPLETE_SECURITY_EXCLUSION_COUNT = (
    FINAL_SECURITY_EXCLUSION_COUNT + BODY_PHISHING_EXCLUSION_COUNT
)
COMPLETE_SAFE_NEW_IMPORTS = EXPECTED_NEW_IMPORTS - COMPLETE_SECURITY_EXCLUSION_COUNT
COMPLETE_SAFE_TARGET_TOTAL = EXPECTED_TARGET_TOTAL - COMPLETE_SECURITY_EXCLUSION_COUNT
SOURCE_74_ATTEMPTED_AT = "2026-09-17T05:29:46+00:00"
SOURCE_74_ERROR = SOURCE_65_ERROR
SOURCE_103_ATTEMPTED_AT = "2026-09-17T05:44:54+00:00"
SOURCE_103_ERROR = SOURCE_65_ERROR
SOURCE_954_ITEM_KEY = '0000000000000000000000000000000000000000000000000000000000002cef'
SOURCE_954_MESSAGE_ID = '<example-c694a212@example.org>'
SOURCE_1632_ID = 1632
SOURCE_1632_ITEM_KEY = (
    '000000000000000000000000000000000000000000000000000000000000dfb7'
)
SOURCE_1632_MESSAGE_ID = '<example-34730551@example.org>'
SOURCE_1632_INTERNAL_DATE_MS = "1777993591000"
SOURCE_1632_HEADERS = {
    "Message-ID": SOURCE_1632_MESSAGE_ID,
    "Subject": 'Synthetic migration example',
    "Date": "Tue, 05 May 2026 17:06:31 +0200",
    "From": '"Example sender" <example-bbbe7b1c@example.org>',
    "To": 'example-b54b38f4@example.org',
}
SOURCE_1632_MIN_ABSENCE_AGE_SECONDS = 300
SOURCE_1632_ZERO_RECHECK_SECONDS = 30
GMAIL_REJECTED_ATTACHMENT_EXCLUSION_COUNT = 1
GMAIL_REJECTED_ATTACHMENT_EXCLUSION_IDS = {1857}
GMAIL_REJECTED_ATTACHMENT_EXCLUSIONS_SHA256 = (
    '00000000000000000000000000000000000000000000000000000000000038d0'
)
SOURCE_1857_ITEM_KEY = (
    '0000000000000000000000000000000000000000000000000000000000004614'
)
SOURCE_1857_MESSAGE_ID = '<example-ac2d347a@example.org>'
SOURCE_1857_ATTEMPTED_AT = "2026-09-17T08:35:50+00:00"
SOURCE_1857_ERROR = SOURCE_65_ERROR
SOURCE_1857_PRETRANSITION_CHECKPOINT_SHA256 = (
    '0000000000000000000000000000000000000000000000000000000000003b6d'
)
COMPLETE_LOCAL_ONLY_COUNT = (
    COMPLETE_SECURITY_EXCLUSION_COUNT + GMAIL_REJECTED_ATTACHMENT_EXCLUSION_COUNT
)
POST_REJECTION_SAFE_NEW_IMPORTS = EXPECTED_NEW_IMPORTS - COMPLETE_LOCAL_ONLY_COUNT
POST_REJECTION_SAFE_TARGET_TOTAL = EXPECTED_TARGET_TOTAL - COMPLETE_LOCAL_ONLY_COUNT


class ImportSafetyError(RuntimeError):
    """Raised when execution cannot continue without risking drift or duplicates."""


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
        raise ImportSafetyError(f"Cannot read valid JSON from {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ImportSafetyError(f"Expected a JSON object in {path}.")
    return value


def load_security_exclusions(rows: list[dict]) -> dict[str, Any]:
    if sha256_file(SECURITY_EXCLUSIONS) != SECURITY_EXCLUSIONS_SHA256:
        raise ImportSafetyError("Security-exclusion evidence file hash changed.")
    document = load_json(SECURITY_EXCLUSIONS)
    expected_header = {
        "schema_version": 1,
        "source_mailbox": DESTINATION,
        "source_root": str(SOURCE_ROOT),
        "gmail_original_target_before_security_exclusions": EXPECTED_TARGET_TOTAL,
        "gmail_original_target_after_security_exclusions": EFFECTIVE_TARGET_TOTAL,
        "security_exclusion_count": SECURITY_EXCLUSION_COUNT,
        "security_exclusion_source_ids": sorted(SECURITY_EXCLUSION_IDS),
    }
    for field, value in expected_header.items():
        if document.get(field) != value:
            raise ImportSafetyError(
                f"Security-exclusion evidence field {field} changed."
            )
    if document.get("gmail_blocked_attachment_policy_url") != (
        "https://support.google.com/mail/answer/6590"
    ):
        raise ImportSafetyError("Security-exclusion policy URL changed.")
    if document.get("policy") != (
        "Do not bypass Gmail delivery scanning for disguised executable, script, "
        "library, screen-saver, legacy executable archive, or virtual-disk "
        "attachments. Preserve each original EML unchanged in the source archive "
        "and exclude it from Gmail."
    ):
        raise ImportSafetyError("Security-exclusion policy text changed.")
    items = document.get("items")
    if not isinstance(items, list) or len(items) != SECURITY_EXCLUSION_COUNT:
        raise ImportSafetyError("Security-exclusion evidence must contain 20 rows.")
    if {int(item.get("source_id", -1)) for item in items} != SECURITY_EXCLUSION_IDS:
        raise ImportSafetyError("Security-exclusion source IDs changed.")

    rows_by_id = {int(row["source_id"]): row for row in rows}
    published_suffixes = {".exe", ".bat", ".vbe", ".dll", ".scr", ".js"}
    for item in items:
        source_id = int(item["source_id"])
        row = rows_by_id[source_id]
        for field in ("item_key", "relative_path", "source_sha256", "message_id"):
            if item.get(field) != row.get(field):
                raise ImportSafetyError(
                    f"Security-exclusion source {source_id} field {field} changed."
                )
        source_path = SOURCE_ROOT / row["relative_path"]
        message = BytesParser(policy=policy.default).parsebytes(source_path.read_bytes())
        parts = list(message.walk())
        part_index = int(item.get("attachment_part_index", -1))
        if not 0 <= part_index < len(parts):
            raise ImportSafetyError(
                f"Security-exclusion source {source_id} attachment index changed."
            )
        part = parts[part_index]
        attachment = part.get_payload(decode=True) or b""
        attachment_checks = {
            "attachment_filename": str(part.get_filename() or ""),
            "attachment_content_type": part.get_content_type(),
            "attachment_size_bytes": len(attachment),
            "attachment_sha256": sha256_bytes(attachment),
        }
        for field, value in attachment_checks.items():
            if item.get(field) != value:
                raise ImportSafetyError(
                    f"Security-exclusion source {source_id} field {field} changed."
                )
        if item.get("source_preservation") != "original_eml_unchanged_local_only":
            raise ImportSafetyError(
                f"Security-exclusion source {source_id} preservation policy changed."
            )
        expected_classification = (
            "disguised_virtual_disk_security_risk"
            if source_id == 1345
            else "gmail_published_blocked_type_inside_archive"
        )
        if item.get("classification") != expected_classification:
            raise ImportSafetyError(
                f"Security-exclusion source {source_id} classification changed."
            )
        if item.get("archive_magic") not in {"zip", "rar", "ace"}:
            raise ImportSafetyError(
                f"Security-exclusion source {source_id} archive type changed."
            )
        members = item.get("blocked_members")
        if not isinstance(members, list) or not members:
            raise ImportSafetyError(
                f"Security-exclusion source {source_id} lacks blocked members."
            )
        suffixes = {Path(str(member)).suffix.lower() for member in members}
        if source_id == 1345:
            if suffixes != {".vhdx"}:
                raise ImportSafetyError("Source 1345 virtual-disk evidence changed.")
        elif not suffixes.intersection(published_suffixes):
            raise ImportSafetyError(
                f"Security-exclusion source {source_id} lacks a blocked suffix."
            )
    return document


def load_html_phishing_exclusions(rows: list[dict]) -> dict[str, Any]:
    if sha256_file(HTML_PHISHING_EXCLUSIONS) != HTML_PHISHING_EXCLUSIONS_SHA256:
        raise ImportSafetyError("HTML-phishing evidence file hash changed.")
    document = load_json(HTML_PHISHING_EXCLUSIONS)
    expected_header = {
        "schema_version": 1,
        "source_mailbox": DESTINATION,
        "source_root": str(SOURCE_ROOT),
        "security_exclusion_count": HTML_PHISHING_EXCLUSION_COUNT,
        "security_exclusion_source_ids": sorted(HTML_PHISHING_EXCLUSION_IDS),
        "observed_gmail_rejection_source_id": 74,
        "policy": (
            "Do not upload HTML attachments that collect mailbox passwords or "
            "submit credentials to external endpoints. Preserve each original "
            "EML unchanged in the local source archive and exclude it from Gmail."
        ),
    }
    for field, value in expected_header.items():
        if document.get(field) != value:
            raise ImportSafetyError(f"HTML-phishing evidence field {field} changed.")
    items = document.get("items")
    if (
        not isinstance(items, list)
        or len(items) != HTML_PHISHING_EXCLUSION_COUNT
        or {int(item.get("source_id", -1)) for item in items}
        != HTML_PHISHING_EXCLUSION_IDS
    ):
        raise ImportSafetyError("HTML-phishing evidence rows changed.")
    rows_by_id = {int(row["source_id"]): row for row in rows}
    telegram_ids = {74, 76, 146, 147, 188, 333, 347}
    external_marker_by_id = {
        1015: b"smartforms.dev/submit",
        1022: b"thedemocraticmirror.com",
        1479: b"xmlhttprequest",
        1480: b"api.web3forms.com/submit",
        1966: b"formspree.io/f/",
        1976: b"formspree.io/f/",
    }
    for item in items:
        source_id = int(item["source_id"])
        row = rows_by_id[source_id]
        for field in ("item_key", "relative_path", "source_sha256", "message_id"):
            if item.get(field) != row.get(field):
                raise ImportSafetyError(
                    f"HTML-phishing source {source_id} field {field} changed."
                )
        source_path = SOURCE_ROOT / row["relative_path"]
        message = BytesParser(policy=policy.default).parsebytes(source_path.read_bytes())
        parts = list(message.walk())
        part_index = int(item.get("attachment_part_index", -1))
        if not 0 <= part_index < len(parts):
            raise ImportSafetyError(
                f"HTML-phishing source {source_id} attachment index changed."
            )
        part = parts[part_index]
        attachment = part.get_payload(decode=True) or b""
        attachment_checks = {
            "attachment_filename": str(part.get_filename() or ""),
            "attachment_content_type": part.get_content_type(),
            "attachment_size_bytes": len(attachment),
            "attachment_sha256": sha256_bytes(attachment),
            "source_preservation": "original_eml_unchanged_local_only",
        }
        for field, value in attachment_checks.items():
            if item.get(field) != value:
                raise ImportSafetyError(
                    f"HTML-phishing source {source_id} field {field} changed."
                )
        lowered = attachment.lower()
        if b"password" not in lowered:
            raise ImportSafetyError(
                f"HTML-phishing source {source_id} lost its password marker."
            )
        if source_id in telegram_ids:
            expected_classification = (
                "credential_phishing_html_telegram_exfiltration"
            )
            required_markers = (b"api.telegram.org", b"sendmessage")
        elif source_id == 469:
            expected_classification = (
                "credential_phishing_html_obfuscated_submission"
            )
            required_markers = (b"blackhackertools.com", b"handlelogin", b"var _0x")
        else:
            expected_classification = (
                "credential_phishing_html_external_form_exfiltration"
            )
            required_markers = (external_marker_by_id[source_id],)
        if item.get("classification") != expected_classification or any(
            marker not in lowered for marker in required_markers
        ):
            raise ImportSafetyError(
                f"HTML-phishing source {source_id} detection evidence changed."
            )
        expected_outcome = (
            "definite_gmail_http_400_invalid_attachment_no_message_id"
            if source_id == 74
            else "not_attempted_preemptive_security_exclusion"
        )
        if item.get("gmail_outcome_at_detection") != expected_outcome:
            raise ImportSafetyError(
                f"HTML-phishing source {source_id} Gmail outcome changed."
            )
        if source_id == 74:
            rejection = item.get("gmail_rejection")
            if rejection != {
                "attempted_at": SOURCE_74_ATTEMPTED_AT,
                "http_status": 400,
                "error": SOURCE_74_ERROR,
                "upload_mode": "resumable_rfc822",
                "gmail_message_id_returned": False,
            }:
                raise ImportSafetyError("HTML-phishing source 74 rejection changed.")
    return document


def load_html_redirect_exclusions(rows: list[dict]) -> dict[str, Any]:
    if sha256_file(HTML_REDIRECT_EXCLUSIONS) != HTML_REDIRECT_EXCLUSIONS_SHA256:
        raise ImportSafetyError("HTML-redirect evidence file hash changed.")
    document = load_json(HTML_REDIRECT_EXCLUSIONS)
    expected_header = {
        "schema_version": 1,
        "source_mailbox": DESTINATION,
        "source_root": str(SOURCE_ROOT),
        "security_exclusion_count": HTML_REDIRECT_EXCLUSION_COUNT,
        "security_exclusion_source_ids": sorted(HTML_REDIRECT_EXCLUSION_IDS),
        "policy": (
            "Keep HTML attachments that immediately load unrelated external "
            "phishing infrastructure out of Gmail. Preserve each original EML "
            "unchanged in the local source archive."
        ),
    }
    for field, value in expected_header.items():
        if document.get(field) != value:
            raise ImportSafetyError(f"HTML-redirect evidence field {field} changed.")
    items = document.get("items")
    if (
        not isinstance(items, list)
        or len(items) != HTML_REDIRECT_EXCLUSION_COUNT
        or {int(item.get("source_id", -1)) for item in items}
        != HTML_REDIRECT_EXCLUSION_IDS
    ):
        raise ImportSafetyError("HTML-redirect evidence rows changed.")
    rows_by_id = {int(row["source_id"]): row for row in rows}
    required_marker_by_id = {
        1052: b"ksdyu8372839-8dbslymhni.edgeone.app",
        1063: b"redircpapp.co.za",
        1199: b"helutran.com",
        1458: b"jejuair.tvbnn.com",
    }
    for item in items:
        source_id = int(item["source_id"])
        row = rows_by_id[source_id]
        for field in ("item_key", "relative_path", "source_sha256", "message_id"):
            if item.get(field) != row.get(field):
                raise ImportSafetyError(
                    f"HTML-redirect source {source_id} field {field} changed."
                )
        message = BytesParser(policy=policy.default).parsebytes(
            (SOURCE_ROOT / row["relative_path"]).read_bytes()
        )
        parts = list(message.walk())
        part_index = int(item.get("attachment_part_index", -1))
        if not 0 <= part_index < len(parts):
            raise ImportSafetyError(
                f"HTML-redirect source {source_id} attachment index changed."
            )
        part = parts[part_index]
        attachment = part.get_payload(decode=True) or b""
        expected_values = {
            "attachment_filename": str(part.get_filename() or ""),
            "attachment_content_type": part.get_content_type(),
            "attachment_size_bytes": len(attachment),
            "attachment_sha256": sha256_bytes(attachment),
            "source_preservation": "original_eml_unchanged_local_only",
            "gmail_outcome_at_detection": (
                "not_attempted_preemptive_redirect_risk_exclusion"
            ),
        }
        for field, value in expected_values.items():
            if item.get(field) != value:
                raise ImportSafetyError(
                    f"HTML-redirect source {source_id} field {field} changed."
                )
        lowered = attachment.lower()
        expected_classification = (
            "html_external_iframe_phishing_lure"
            if source_id == 1052
            else "html_meta_refresh_phishing_lure"
        )
        structural_marker = b"<iframe" if source_id == 1052 else b"http-equiv=\"refresh\""
        if (
            item.get("classification") != expected_classification
            or required_marker_by_id[source_id] not in lowered
            or structural_marker not in lowered
        ):
            raise ImportSafetyError(
                f"HTML-redirect source {source_id} detection evidence changed."
            )
    return document


def load_body_phishing_exclusions(rows: list[dict]) -> dict[str, Any]:
    """Load and revalidate the bounded static evidence for body-link phishing."""
    if sha256_file(BODY_PHISHING_EXCLUSIONS) != BODY_PHISHING_EXCLUSIONS_SHA256:
        raise ImportSafetyError("Body-phishing evidence file hash changed.")
    document = load_json(BODY_PHISHING_EXCLUSIONS)
    expected_header = {
        "schema_version": 1,
        "source_mailbox": DESTINATION,
        "source_root": str(SOURCE_ROOT),
        "scan_checkpoint_sha256": (
            '00000000000000000000000000000000000000000000000000000000000098be'
        ),
        "pending_rows_scanned": 1634,
        "failed_reference_rows_scanned": 1,
        "parsed_and_source_hash_verified": 1635,
        "security_exclusion_count": BODY_PHISHING_EXCLUSION_COUNT,
        "security_exclusion_source_ids": sorted(BODY_PHISHING_EXCLUSION_IDS),
        "observed_gmail_rejection_source_id": 103,
        "policy": (
            "Keep high-confidence phishing messages with active body links to "
            "unrelated external infrastructure out of Gmail. Preserve each "
            "original EML unchanged in the local source archive and do not "
            "bypass Gmail delivery scanning."
        ),
    }
    for field, value in expected_header.items():
        if document.get(field) != value:
            raise ImportSafetyError(f"Body-phishing evidence field {field} changed.")
    items = document.get("items")
    if (
        not isinstance(items, list)
        or len(items) != BODY_PHISHING_EXCLUSION_COUNT
        or {int(item.get("source_id", -1)) for item in items}
        != BODY_PHISHING_EXCLUSION_IDS
    ):
        raise ImportSafetyError("Body-phishing evidence rows changed.")

    rows_by_id = {int(row["source_id"]): row for row in rows}
    for item in items:
        source_id = int(item["source_id"])
        row = rows_by_id[source_id]
        for field in ("item_key", "relative_path", "source_sha256", "message_id"):
            if item.get(field) != row.get(field):
                raise ImportSafetyError(
                    f"Body-phishing source {source_id} field {field} changed."
                )
        source_path = SOURCE_ROOT / row["relative_path"]
        message = BytesParser(policy=policy.default).parsebytes(source_path.read_bytes())
        parts = list(message.walk())
        part_index = int(item.get("body_part_index", -1))
        if not 0 <= part_index < len(parts):
            raise ImportSafetyError(
                f"Body-phishing source {source_id} body index changed."
            )
        part = parts[part_index]
        body = part.get_payload(decode=True) or b""
        expected_values = {
            "from": str(message.get("From", "")),
            "subject": str(message.get("Subject", "")),
            "received_spf": str(message.get("Received-SPF", "")),
            "body_content_type": part.get_content_type(),
            "body_size_bytes": len(body),
            "body_sha256": sha256_bytes(body),
            "source_preservation": "original_eml_unchanged_local_only",
        }
        for field, value in expected_values.items():
            if item.get(field) != value:
                raise ImportSafetyError(
                    f"Body-phishing source {source_id} field {field} changed."
                )
        if part.get_content_type() not in {"text/html", "text/plain"}:
            raise ImportSafetyError(
                f"Body-phishing source {source_id} no longer has a text body."
            )
        if any(
            candidate.get_content_disposition() == "attachment"
            for candidate in parts
        ):
            raise ImportSafetyError(
                f"Body-phishing source {source_id} unexpectedly has an attachment."
            )
        link_hosts = item.get("link_hosts")
        lowered_body = body.lower()
        if (
            not isinstance(link_hosts, list)
            or not link_hosts
            or any(
                str(host).encode("ascii", "strict").lower() not in lowered_body
                for host in link_hosts
            )
        ):
            raise ImportSafetyError(
                f"Body-phishing source {source_id} link-host evidence changed."
            )
        indicators = item.get("indicators")
        if (
            item.get("classification") not in BODY_PHISHING_CLASSIFICATIONS
            or not isinstance(item.get("reason"), str)
            or not item.get("reason")
            or not isinstance(indicators, list)
            or "active_external_link_in_non_attachment_body" not in indicators
            or len(indicators) < 3
        ):
            raise ImportSafetyError(
                f"Body-phishing source {source_id} indicators changed."
            )
        expected_outcome = (
            "definite_gmail_http_400_invalid_attachment_no_message_id"
            if source_id == 103
            else "not_attempted_preemptive_security_exclusion"
        )
        if item.get("gmail_outcome_at_detection") != expected_outcome:
            raise ImportSafetyError(
                f"Body-phishing source {source_id} Gmail outcome changed."
            )
        if source_id == 103:
            rejection = item.get("gmail_rejection")
            if rejection != {
                "attempted_at": SOURCE_103_ATTEMPTED_AT,
                "http_status": 400,
                "error": SOURCE_103_ERROR,
                "upload_mode": "resumable_rfc822",
                "gmail_message_id_returned": False,
            }:
                raise ImportSafetyError("Body-phishing source 103 rejection changed.")
    return document


def load_gmail_rejected_attachment_exclusions(rows: list[dict]) -> dict[str, Any]:
    """Load and revalidate the one definite late Gmail attachment rejection."""
    if (
        sha256_file(GMAIL_REJECTED_ATTACHMENT_EXCLUSIONS)
        != GMAIL_REJECTED_ATTACHMENT_EXCLUSIONS_SHA256
    ):
        raise ImportSafetyError("Gmail-rejected attachment evidence file hash changed.")
    document = load_json(GMAIL_REJECTED_ATTACHMENT_EXCLUSIONS)
    expected_header = {
        "schema_version": 1,
        "source_mailbox": DESTINATION,
        "source_root": str(SOURCE_ROOT),
        "gmail_policy_url": "https://support.google.com/mail/answer/6590",
        "policy": (
            "Keep a message local-only when Gmail users.messages.import definitively "
            "rejects the original RFC822 bytes with HTTP 400 Invalid attachment and "
            "returns no Gmail message ID. Preserve the original EML unchanged and do "
            "not strip, rewrite, or bypass scanning for the attachment."
        ),
        "gmail_rejected_attachment_count": (
            GMAIL_REJECTED_ATTACHMENT_EXCLUSION_COUNT
        ),
        "gmail_rejected_attachment_source_ids": sorted(
            GMAIL_REJECTED_ATTACHMENT_EXCLUSION_IDS
        ),
    }
    for field, value in expected_header.items():
        if document.get(field) != value:
            raise ImportSafetyError(
                f"Gmail-rejected attachment evidence field {field} changed."
            )
    items = document.get("items")
    if (
        not isinstance(items, list)
        or len(items) != GMAIL_REJECTED_ATTACHMENT_EXCLUSION_COUNT
        or {int(item.get("source_id", -1)) for item in items}
        != GMAIL_REJECTED_ATTACHMENT_EXCLUSION_IDS
    ):
        raise ImportSafetyError("Gmail-rejected attachment evidence rows changed.")

    rows_by_id = {int(row["source_id"]): row for row in rows}
    item = items[0]
    row = rows_by_id[1857]
    for field in ("item_key", "relative_path", "source_sha256", "message_id"):
        if item.get(field) != row.get(field):
            raise ImportSafetyError(
                f"Gmail-rejected source 1857 field {field} changed."
            )
    if (
        item.get("item_key") != SOURCE_1857_ITEM_KEY
        or item.get("message_id") != SOURCE_1857_MESSAGE_ID
    ):
        raise ImportSafetyError("Gmail-rejected source 1857 identity changed.")

    source_path = SOURCE_ROOT / row["relative_path"]
    message = BytesParser(policy=policy.default).parsebytes(source_path.read_bytes())
    parts = list(message.walk())
    part_index = int(item.get("attachment_part_index", -1))
    if not 0 <= part_index < len(parts):
        raise ImportSafetyError("Gmail-rejected source 1857 attachment index changed.")
    part = parts[part_index]
    attachment = part.get_payload(decode=True) or b""
    encoded_payload = part.get_payload(decode=False)
    try:
        strict_decoded = base64.b64decode(
            "".join(str(encoded_payload).split()), validate=True
        )
    except (ValueError, TypeError) as exc:
        raise ImportSafetyError(
            "Gmail-rejected source 1857 attachment base64 is invalid."
        ) from exc
    attachment_checks = {
        "attachment_filename": str(part.get_filename() or ""),
        "attachment_content_type": part.get_content_type(),
        "attachment_disposition": str(part.get_content_disposition() or ""),
        "attachment_size_bytes": len(attachment),
        "attachment_sha256": sha256_bytes(attachment),
        "attachment_magic_hex": attachment[:8].hex(),
    }
    for field, value in attachment_checks.items():
        if item.get(field) != value:
            raise ImportSafetyError(
                f"Gmail-rejected source 1857 field {field} changed."
            )
    if strict_decoded != attachment:
        raise ImportSafetyError(
            "Gmail-rejected source 1857 strict base64 bytes changed."
        )

    expected_indicators = [
        "gmail_http_400_invalid_attachment_no_message_id",
        "password_encrypted_legacy_ole_spreadsheet",
        "vba_project_present_no_executable_statements_in_recovered_source",
        "two_embedded_ooxml_spreadsheets",
        "embedded_ole_acrobat_pdf",
    ]
    if (
        item.get("classification")
        != "gmail_definite_invalid_attachment_rejection_nested_ole_spreadsheet"
        or item.get("indicators") != expected_indicators
        or not isinstance(item.get("reason"), str)
        or not item.get("reason")
        or item.get("gmail_outcome_at_detection")
        != "definite_gmail_http_400_invalid_attachment_no_message_id"
        or item.get("source_preservation")
        != "original_eml_unchanged_local_only"
    ):
        raise ImportSafetyError(
            "Gmail-rejected source 1857 classification evidence changed."
        )
    if item.get("gmail_rejection") != {
        "attempted_at": SOURCE_1857_ATTEMPTED_AT,
        "http_status": 400,
        "error": SOURCE_1857_ERROR,
        "upload_mode": "resumable_rfc822",
        "gmail_message_id_returned": False,
    }:
        raise ImportSafetyError("Gmail-rejected source 1857 receipt changed.")
    inert_analysis = item.get("inert_analysis")
    if (
        not isinstance(inert_analysis, dict)
        or inert_analysis.get("password_encrypted") is not True
        or inert_analysis.get("password_key_types") != ["password"]
        or inert_analysis.get("strict_base64_valid") is not True
        or inert_analysis.get("vba_project_present") is not True
        or inert_analysis.get("vba_source_executable_statements_observed")
        is not False
        or inert_analysis.get("vba_stomping_detected") is not False
        or inert_analysis.get("xlm_macros_detected") is not False
        or inert_analysis.get("blocked_executable_filename_observed") is not False
        or inert_analysis.get("google_rejection_trigger_independently_known")
        is not False
        or len(inert_analysis.get("embedded_ooxml_packages", [])) != 2
        or inert_analysis.get("embedded_ole_object", {}).get("sha256")
        != '00000000000000000000000000000000000000000000000000000000000054f0'
        or inert_analysis.get("embedded_pdf", {}).get("sha256")
        != '0000000000000000000000000000000000000000000000000000000000008a24'
    ):
        raise ImportSafetyError(
            "Gmail-rejected source 1857 inert analysis evidence changed."
        )
    return document


def write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def preserve_content_addressed_backup(
    backup_path: Path, content: bytes, description: str
) -> None:
    """Create a read-only backup once and reject any same-name content drift."""
    if backup_path.exists():
        if backup_path.read_bytes() != content:
            raise ImportSafetyError(f"{description} backup path already drifted.")
    else:
        backup_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            descriptor = os.open(
                backup_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o400,
            )
        except FileExistsError:
            if backup_path.read_bytes() != content:
                raise ImportSafetyError(f"{description} backup path already drifted.")
        else:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
    os.chmod(backup_path, 0o400)
    if backup_path.read_bytes() != content:
        raise ImportSafetyError(f"{description} backup verification failed.")


def validate_credentials(path: Path) -> None:
    data = load_json(path)
    installed = data.get("installed")
    if not isinstance(installed, dict):
        raise ImportSafetyError("OAuth JSON must be a Desktop app client.")
    if str(installed.get("client_id", "")) != OAUTH_CLIENT_ID:
        raise ImportSafetyError("OAuth credentials do not match the audited client ID.")


def current_pilot_receipts() -> dict[str, dict[str, str]]:
    pilot_manifest = load_json(PILOT_MANIFEST)
    pilot_checkpoint = load_json(PILOT_CHECKPOINT)
    if pilot_checkpoint.get("pilot_status") != "verified_complete":
        raise ImportSafetyError("The five-message pilot is no longer verified complete.")
    states = pilot_checkpoint.get("messages", {})
    receipts = {}
    for row in pilot_manifest.get("messages", []):
        pilot_id = str(row.get("pilot_id", ""))
        state = states.get(pilot_id, {})
        if state.get("status") != "verified" or not state.get("gmail_message_id"):
            raise ImportSafetyError(f"Pilot {pilot_id} lost its verified Gmail receipt.")
        receipts[str(row["sha256"])] = {
            "pilot_id": pilot_id,
            "gmail_message_id": str(state["gmail_message_id"]),
            "message_id": str(row["rfc822_message_id"]),
        }
    if len(receipts) != 5:
        raise ImportSafetyError("Expected exactly five verified pilot receipts.")
    return receipts


def expected_import_priority(row: dict) -> tuple[int, int]:
    source_id = int(row["source_id"])
    if source_id in DATE_UTC_NORMALIZATION_IDS:
        return (0, source_id)
    if "cafe24_received_fold_space_v1" in row.get("repairs", []):
        return (1, source_id)
    if int(row["source_size_bytes"]) >= 25_000_000:
        return (2, source_id)
    return (3, source_id)


def validate_manifest_header(manifest: dict[str, Any], manifest_path: Path) -> list[dict]:
    if manifest_path.resolve() != CANONICAL_MANIFEST.resolve():
        raise ImportSafetyError("Manifest path is not the canonical full-import manifest.")
    expected = {
        "source_mailbox": DESTINATION,
        "expected_destination": DESTINATION,
        "source_root": str(SOURCE_ROOT),
        "expected_source_folder": SOURCE_FOLDER,
        "source_eml_count": SOURCE_COUNT,
        "source_total_bytes": SOURCE_BYTES,
        "oauth_client_id": OAUTH_CLIENT_ID,
        "expected_checkpoint": str(CANONICAL_CHECKPOINT),
    }
    for field, value in expected.items():
        if manifest.get(field) != value:
            raise ImportSafetyError(f"Manifest field {field} no longer matches the audit.")
    if manifest.get("reconciliation") != {
        "already_imported_verified_pilot": 5,
        "new_api_imports": EXPECTED_NEW_IMPORTS,
        "semantic_duplicates_skipped": 3,
        "source_files": SOURCE_COUNT,
        "target_gmail_messages_from_archive": EXPECTED_TARGET_TOTAL,
    }:
        raise ImportSafetyError("Manifest reconciliation is not 2005 = 5 + 3 + 1997.")
    rows = manifest.get("messages")
    if not isinstance(rows, list) or len(rows) != SOURCE_COUNT:
        raise ImportSafetyError("Manifest must contain exactly 2,005 source rows.")
    if len({row.get("item_key") for row in rows}) != SOURCE_COUNT:
        raise ImportSafetyError("Manifest item keys are not unique.")
    if len({row.get("source_id") for row in rows}) != SOURCE_COUNT:
        raise ImportSafetyError("Manifest source IDs are not unique.")
    actions = Counter(str(row.get("action")) for row in rows)
    if actions != Counter(
        {
            "import": EXPECTED_NEW_IMPORTS,
            "already_imported_verified_pilot": 5,
            "skip_semantic_duplicate": 3,
        }
    ):
        raise ImportSafetyError(f"Manifest action partition changed: {dict(actions)}")

    pilot_receipts = current_pilot_receipts()
    seen_pilot_hashes = set()
    for row in rows:
        source_id = int(row["source_id"])
        source_sha = str(row["source_sha256"])
        if source_sha in pilot_receipts:
            receipt = pilot_receipts[source_sha]
            seen_pilot_hashes.add(source_sha)
            if (
                row.get("action") != "already_imported_verified_pilot"
                or row.get("pilot_id") != receipt["pilot_id"]
                or row.get("gmail_message_id") != receipt["gmail_message_id"]
                or row.get("message_id") != receipt["message_id"]
            ):
                raise ImportSafetyError(
                    f"Manifest pilot mapping changed at source {source_id}."
                )
        elif source_id in DUPLICATE_SKIP_TO_KEEP:
            kept_id = DUPLICATE_SKIP_TO_KEEP[source_id]
            if (
                row.get("action") != "skip_semantic_duplicate"
                or int(row.get("duplicate_of_source_id", -1)) != kept_id
            ):
                raise ImportSafetyError(
                    f"Manifest duplicate mapping changed at source {source_id}."
                )
        elif row.get("action") != "import":
            raise ImportSafetyError(
                f"Manifest action changed for ordinary source {source_id}."
            )
    if seen_pilot_hashes != set(pilot_receipts):
        raise ImportSafetyError("Manifest does not contain the exact five pilot hashes.")

    expected_import_rows = sorted(
        (row for row in rows if row["action"] == "import"),
        key=expected_import_priority,
    )
    for expected_order, row in enumerate(expected_import_rows, start=1):
        if int(row.get("import_order", -1)) != expected_order:
            raise ImportSafetyError(
                f"Manifest import order changed at source {row['source_id']}."
            )
    import_orders = sorted(
        int(row["import_order"]) for row in rows if row["action"] == "import"
    )
    if import_orders != list(range(1, EXPECTED_NEW_IMPORTS + 1)):
        raise ImportSafetyError("Manifest import order is not exactly 1 through 1997.")
    selected_ids = [
        str(row["message_id"])
        for row in rows
        if row["action"] != "skip_semantic_duplicate"
    ]
    if len(selected_ids) != EXPECTED_TARGET_TOTAL or len(set(selected_ids)) != len(
        selected_ids
    ):
        raise ImportSafetyError("Selected Message-IDs are not exactly 2,002 unique values.")
    return rows


def validate_source_snapshot(rows: list[dict]) -> None:
    paths = archive_files()
    rows_by_id = {int(row["source_id"]): row for row in rows}
    comparable_fields = (
        "source_id",
        "relative_path",
        "source_size_bytes",
        "source_sha256",
        "prepared_size_bytes",
        "prepared_sha256",
        "repairs",
        "message_id",
        "date_header",
        "date_policy",
        "expected_internal_date_ms",
        "body_sha256",
    )
    for path in paths:
        _, current = prepared_record(path)
        frozen = rows_by_id[int(current["source_id"])]
        for field in comparable_fields:
            if current.get(field) != frozen.get(field):
                raise ImportSafetyError(
                    f"Source drift for numeric ID {current['source_id']} field {field}."
                )
        if int(current["prepared_size_bytes"]) > 150 * 1024 * 1024:
            raise ImportSafetyError(f"Source {current['source_id']} exceeds 150 MiB.")


def new_checkpoint(
    manifest_sha256: str,
    manifest: dict[str, Any],
    rows: list[dict],
    confirmations: dict[str, Any],
) -> dict[str, Any]:
    states = {}
    for row in rows:
        action = row["action"]
        state = {
            "source_id": row["source_id"],
            "relative_path": row["relative_path"],
            "source_sha256": row["source_sha256"],
            "message_id": row["message_id"],
            "action": action,
        }
        if action == "already_imported_verified_pilot":
            state.update(
                status="verified_pilot",
                gmail_message_id=row["gmail_message_id"],
                pilot_id=row["pilot_id"],
            )
        elif action == "skip_semantic_duplicate":
            state.update(
                status="skipped_semantic_duplicate",
                duplicate_of_source_id=row["duplicate_of_source_id"],
                duplicate_of_source_sha256=row["duplicate_of_source_sha256"],
            )
        else:
            state["status"] = "pending"
        states[row["item_key"]] = state
    now = utc_now()
    return {
        "schema_version": 1,
        "created_at": now,
        "updated_at": now,
        "destination": DESTINATION,
        "oauth_client_id": OAUTH_CLIENT_ID,
        "manifest_sha256": manifest_sha256,
        "source_eml_count": SOURCE_COUNT,
        "target_gmail_messages": EXPECTED_TARGET_TOTAL,
        "new_api_imports": EXPECTED_NEW_IMPORTS,
        "confirmations": confirmations,
        "batch_sequence": 0,
        "verification_gate": None,
        "verified_batches": [],
        "states": states,
    }


def load_checkpoint(
    checkpoint_path: Path,
    manifest_sha256: str,
    manifest: dict[str, Any],
    rows: list[dict],
    initial_confirmations: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if checkpoint_path.exists():
        checkpoint = load_json(checkpoint_path)
    else:
        if initial_confirmations is None:
            raise ImportSafetyError("Full-import checkpoint does not exist yet.")
        checkpoint = new_checkpoint(
            manifest_sha256, manifest, rows, initial_confirmations
        )
    expected_header = {
        "destination": DESTINATION,
        "oauth_client_id": OAUTH_CLIENT_ID,
        "manifest_sha256": manifest_sha256,
        "source_eml_count": SOURCE_COUNT,
        "target_gmail_messages": EXPECTED_TARGET_TOTAL,
        "new_api_imports": EXPECTED_NEW_IMPORTS,
    }
    for field, value in expected_header.items():
        if checkpoint.get(field) != value:
            raise ImportSafetyError(f"Checkpoint field {field} does not match the manifest.")
    if checkpoint.get("confirmations") != {
        "baseline_had_no_preexisting_archive_copies": True,
        "semantic_duplicate_skips": 3,
        "storage_at_least_1_3_gb": True,
    }:
        raise ImportSafetyError("Checkpoint migration confirmations are missing or changed.")
    if not isinstance(checkpoint.get("batch_sequence"), int):
        raise ImportSafetyError("Checkpoint batch_sequence is invalid.")
    if not isinstance(checkpoint.get("verified_batches"), list):
        raise ImportSafetyError("Checkpoint verified_batches is invalid.")
    states = checkpoint.get("states")
    expected_keys = {str(row["item_key"]) for row in rows}
    if not isinstance(states, dict) or set(states) != expected_keys:
        raise ImportSafetyError("Checkpoint rows do not match the manifest.")

    security_policy = checkpoint.get("security_attachment_policy")
    security_items_by_id: dict[int, dict[str, Any]] = {}
    if security_policy is not None:
        if not isinstance(security_policy, dict):
            raise ImportSafetyError("Checkpoint security-attachment policy is invalid.")
        security_evidence = load_security_exclusions(rows)
        security_items_by_id = {
            int(item["source_id"]): item for item in security_evidence["items"]
        }
        expected_security_policy = {
            "status": "applied",
            "security_exclusion_count": SECURITY_EXCLUSION_COUNT,
            "security_exclusion_source_ids": sorted(SECURITY_EXCLUSION_IDS),
            "evidence_manifest": str(SECURITY_EXCLUSIONS),
            "evidence_manifest_sha256": SECURITY_EXCLUSIONS_SHA256,
            "original_target_gmail_messages": EXPECTED_TARGET_TOTAL,
            "effective_target_gmail_messages": EFFECTIVE_TARGET_TOTAL,
            "original_new_api_imports": EXPECTED_NEW_IMPORTS,
            "effective_new_api_imports": EFFECTIVE_NEW_IMPORTS,
            "source_preservation": "original_eml_unchanged_local_only",
            "gmail_write_policy": "users.messages.import_only_no_scanning_bypass",
        }
        for field, value in expected_security_policy.items():
            if security_policy.get(field) != value:
                raise ImportSafetyError(
                    f"Checkpoint security policy field {field} changed."
                )
        if not isinstance(security_policy.get("applied_at"), str) or not security_policy[
            "applied_at"
        ]:
            raise ImportSafetyError("Checkpoint security policy lacks its applied time.")
        recovery = security_policy.get("blocked_batch_recovery")
        if not isinstance(recovery, dict):
            raise ImportSafetyError("Checkpoint security policy lacks batch recovery.")
        recovery_gate = recovery.get("verification_gate_before_recovery")
        failed_state = recovery.get("failed_source_state_before_recovery")
        if (
            recovery.get("batch_sequence") != 4
            or recovery.get("failed_source_id") != 65
            or recovery.get("failed_http_status") != 400
            or recovery.get("gmail_message_id_returned") is not False
            or not isinstance(recovery.get("gate_cleared_at"), str)
            or recovery.get("gate_cleared_at") != security_policy.get("applied_at")
            or not isinstance(recovery_gate, dict)
            or not isinstance(failed_state, dict)
        ):
            raise ImportSafetyError("Checkpoint security batch-recovery receipt changed.")
        if (
            recovery_gate.get("status") != "blocked"
            or recovery_gate.get("batch_sequence") != 4
            or recovery_gate.get("item_keys") != []
            or recovery_gate.get("source_ids") != []
            or len(recovery_gate.get("planned_item_keys", [])) != 250
            or len(set(recovery_gate.get("planned_item_keys", []))) != 250
            or len(recovery_gate.get("planned_source_ids", [])) != 250
            or len(set(recovery_gate.get("planned_source_ids", []))) != 250
            or len(recovery_gate.get("verified_completed_item_keys", [])) != 179
            or len(set(recovery_gate.get("verified_completed_item_keys", []))) != 179
        ):
            raise ImportSafetyError("Checkpoint archived blocked gate changed.")
        planned_item_keys = recovery_gate["planned_item_keys"]
        planned_source_ids = recovery_gate["planned_source_ids"]
        if any(item_key not in states for item_key in planned_item_keys) or [
            int(states[item_key]["source_id"]) for item_key in planned_item_keys
        ] != [int(source_id) for source_id in planned_source_ids]:
            raise ImportSafetyError("Checkpoint archived gate plan no longer reconciles.")
        source_65_item_key = security_items_by_id[65]["item_key"]
        verified_completed_keys = set(recovery_gate["verified_completed_item_keys"])
        planned_key_set = set(planned_item_keys)
        if (
            source_65_item_key not in planned_key_set
            or source_65_item_key in verified_completed_keys
            or not verified_completed_keys.issubset(planned_key_set)
            or len(planned_key_set - verified_completed_keys - {source_65_item_key}) != 70
        ):
            raise ImportSafetyError("Source 65 is absent from the archived blocked gate.")
        security_ids_in_plan = {
            int(states[item_key]["source_id"])
            for item_key in planned_item_keys
            if int(states[item_key]["source_id"]) in SECURITY_EXCLUSION_IDS
        }
        if security_ids_in_plan != {65, 89, 128, 129, 133, 137}:
            raise ImportSafetyError(
                "Archived blocked gate security exclusions changed."
            )
        expected_unattempted_keys = [
            item_key
            for item_key in planned_item_keys
            if item_key not in verified_completed_keys
            and item_key != source_65_item_key
        ]
        if (
            recovery.get("unattempted_item_keys_at_recovery")
            != expected_unattempted_keys
            or recovery.get("security_exclusion_source_ids_in_blocked_plan")
            != sorted(security_ids_in_plan)
        ):
            raise ImportSafetyError(
                "Checkpoint security recovery partition changed."
            )
        if (
            failed_state.get("source_id") != 65
            or failed_state.get("status") != "failed"
            or failed_state.get("http_status") != 400
            or failed_state.get("gmail_message_id")
            or failed_state.get("error") != SOURCE_65_ERROR
            or failed_state.get("upload_mode") != "resumable_rfc822"
            or failed_state.get("attempted_at") != SOURCE_65_ATTEMPTED_AT
        ):
            raise ImportSafetyError("Archived source 65 failure receipt changed.")
        batch_four_receipts = [
            receipt
            for receipt in checkpoint["verified_batches"]
            if receipt.get("batch_sequence") == 4
        ]
        if (
            len(batch_four_receipts) != 1
            or batch_four_receipts[0].get("item_count") != 179
            or set(batch_four_receipts[0].get("item_keys", []))
            != set(recovery_gate["verified_completed_item_keys"])
            or batch_four_receipts[0].get("verified_at")
            != recovery_gate.get("successful_subset_verified_at")
        ):
            raise ImportSafetyError(
                "Archived blocked gate does not reconcile with verified batch 4."
            )

    html_phishing_policy = checkpoint.get("html_phishing_security_policy")
    html_phishing_items_by_id: dict[int, dict[str, Any]] = {}
    if html_phishing_policy is not None:
        if security_policy is None or not isinstance(html_phishing_policy, dict):
            raise ImportSafetyError(
                "Checkpoint HTML-phishing security policy is invalid."
            )
        html_evidence = load_html_phishing_exclusions(rows)
        html_phishing_items_by_id = {
            int(item["source_id"]): item for item in html_evidence["items"]
        }
        expected_html_policy = {
            "status": "applied",
            "security_exclusion_count": HTML_PHISHING_EXCLUSION_COUNT,
            "security_exclusion_source_ids": sorted(HTML_PHISHING_EXCLUSION_IDS),
            "evidence_manifest": str(HTML_PHISHING_EXCLUSIONS),
            "evidence_manifest_sha256": HTML_PHISHING_EXCLUSIONS_SHA256,
            "original_target_gmail_messages": EXPECTED_TARGET_TOTAL,
            "prior_effective_target_gmail_messages": EFFECTIVE_TARGET_TOTAL,
            "effective_target_gmail_messages": SAFE_TARGET_TOTAL_AFTER_HTML_EXCLUSIONS,
            "original_new_api_imports": EXPECTED_NEW_IMPORTS,
            "prior_effective_new_api_imports": EFFECTIVE_NEW_IMPORTS,
            "effective_new_api_imports": SAFE_NEW_IMPORTS_AFTER_HTML_EXCLUSIONS,
            "total_security_exclusion_count": TOTAL_SECURITY_EXCLUSION_COUNT,
            "source_preservation": "original_eml_unchanged_local_only",
            "gmail_write_policy": "users.messages.import_only_no_scanning_bypass",
        }
        for field, value in expected_html_policy.items():
            if html_phishing_policy.get(field) != value:
                raise ImportSafetyError(
                    f"Checkpoint HTML-phishing policy field {field} changed."
                )
        if not isinstance(html_phishing_policy.get("applied_at"), str) or not (
            html_phishing_policy["applied_at"]
        ):
            raise ImportSafetyError(
                "Checkpoint HTML-phishing policy lacks its applied time."
            )
        recovery = html_phishing_policy.get("blocked_batch_recovery")
        recovery_gate = (
            recovery.get("verification_gate_before_recovery")
            if isinstance(recovery, dict)
            else None
        )
        failed_state = (
            recovery.get("failed_source_state_before_recovery")
            if isinstance(recovery, dict)
            else None
        )
        if (
            not isinstance(recovery, dict)
            or recovery.get("batch_sequence") != 5
            or recovery.get("failed_source_id") != 74
            or recovery.get("failed_http_status") != 400
            or recovery.get("gmail_message_id_returned") is not False
            or recovery.get("gate_cleared_at")
            != html_phishing_policy.get("applied_at")
            or not isinstance(recovery_gate, dict)
            or not isinstance(failed_state, dict)
        ):
            raise ImportSafetyError(
                "Checkpoint HTML-phishing batch-recovery receipt changed."
            )
        if (
            recovery_gate.get("status") != "blocked"
            or recovery_gate.get("batch_sequence") != 5
            or recovery_gate.get("item_keys") != []
            or recovery_gate.get("source_ids") != []
            or len(recovery_gate.get("planned_item_keys", [])) != 250
            or len(set(recovery_gate.get("planned_item_keys", []))) != 250
            or len(recovery_gate.get("planned_source_ids", [])) != 250
            or len(set(recovery_gate.get("planned_source_ids", []))) != 250
            or len(recovery_gate.get("verified_completed_item_keys", [])) != 6
            or len(set(recovery_gate.get("verified_completed_item_keys", []))) != 6
        ):
            raise ImportSafetyError("Checkpoint archived HTML-phishing gate changed.")
        planned_item_keys = recovery_gate["planned_item_keys"]
        planned_source_ids = recovery_gate["planned_source_ids"]
        if any(item_key not in states for item_key in planned_item_keys) or [
            int(states[item_key]["source_id"]) for item_key in planned_item_keys
        ] != [int(source_id) for source_id in planned_source_ids]:
            raise ImportSafetyError(
                "Checkpoint archived HTML-phishing gate plan no longer reconciles."
            )
        source_74_item_key = html_phishing_items_by_id[74]["item_key"]
        verified_completed_keys = set(recovery_gate["verified_completed_item_keys"])
        planned_key_set = set(planned_item_keys)
        expected_unattempted_keys = [
            item_key
            for item_key in planned_item_keys
            if item_key not in verified_completed_keys
            and item_key != source_74_item_key
        ]
        html_ids_in_plan = {
            int(states[item_key]["source_id"])
            for item_key in planned_item_keys
            if int(states[item_key]["source_id"]) in HTML_PHISHING_EXCLUSION_IDS
        }
        if (
            source_74_item_key not in planned_key_set
            or source_74_item_key in verified_completed_keys
            or not verified_completed_keys.issubset(planned_key_set)
            or len(expected_unattempted_keys) != 243
            or html_ids_in_plan != {74, 76, 146, 147, 188, 333}
            or recovery.get("unattempted_item_keys_at_recovery")
            != expected_unattempted_keys
            or recovery.get("security_exclusion_source_ids_in_blocked_plan")
            != sorted(html_ids_in_plan)
        ):
            raise ImportSafetyError(
                "Checkpoint archived HTML-phishing recovery partition changed."
            )
        if (
            failed_state.get("source_id") != 74
            or failed_state.get("status") != "failed"
            or failed_state.get("http_status") != 400
            or failed_state.get("gmail_message_id")
            or failed_state.get("error") != SOURCE_74_ERROR
            or failed_state.get("upload_mode") != "resumable_rfc822"
            or failed_state.get("attempted_at") != SOURCE_74_ATTEMPTED_AT
        ):
            raise ImportSafetyError("Archived source 74 failure receipt changed.")
        batch_five_receipts = [
            receipt
            for receipt in checkpoint["verified_batches"]
            if receipt.get("batch_sequence") == 5
        ]
        if (
            len(batch_five_receipts) != 1
            or batch_five_receipts[0].get("item_count") != 6
            or set(batch_five_receipts[0].get("item_keys", []))
            != verified_completed_keys
            or batch_five_receipts[0].get("verified_at")
            != recovery_gate.get("successful_subset_verified_at")
        ):
            raise ImportSafetyError(
                "Archived HTML-phishing gate does not reconcile with verified batch 5."
            )

    html_redirect_policy = checkpoint.get("html_redirect_security_policy")
    html_redirect_items_by_id: dict[int, dict[str, Any]] = {}
    if html_redirect_policy is not None:
        if html_phishing_policy is None or not isinstance(html_redirect_policy, dict):
            raise ImportSafetyError(
                "Checkpoint HTML-redirect security policy is invalid."
            )
        redirect_evidence = load_html_redirect_exclusions(rows)
        html_redirect_items_by_id = {
            int(item["source_id"]): item for item in redirect_evidence["items"]
        }
        expected_redirect_policy = {
            "status": "applied",
            "security_exclusion_count": HTML_REDIRECT_EXCLUSION_COUNT,
            "security_exclusion_source_ids": sorted(HTML_REDIRECT_EXCLUSION_IDS),
            "evidence_manifest": str(HTML_REDIRECT_EXCLUSIONS),
            "evidence_manifest_sha256": HTML_REDIRECT_EXCLUSIONS_SHA256,
            "original_target_gmail_messages": EXPECTED_TARGET_TOTAL,
            "prior_effective_target_gmail_messages": (
                SAFE_TARGET_TOTAL_AFTER_HTML_EXCLUSIONS
            ),
            "effective_target_gmail_messages": FINAL_SAFE_TARGET_TOTAL,
            "original_new_api_imports": EXPECTED_NEW_IMPORTS,
            "prior_effective_new_api_imports": (
                SAFE_NEW_IMPORTS_AFTER_HTML_EXCLUSIONS
            ),
            "effective_new_api_imports": FINAL_SAFE_NEW_IMPORTS,
            "total_security_exclusion_count": FINAL_SECURITY_EXCLUSION_COUNT,
            "source_preservation": "original_eml_unchanged_local_only",
            "gmail_write_policy": "users.messages.import_only_no_scanning_bypass",
        }
        for field, value in expected_redirect_policy.items():
            if html_redirect_policy.get(field) != value:
                raise ImportSafetyError(
                    f"Checkpoint HTML-redirect policy field {field} changed."
                )
        applied_at = html_redirect_policy.get("applied_at")
        transition = html_redirect_policy.get("checkpoint_transition")
        if (
            not isinstance(applied_at, str)
            or not applied_at
            or not isinstance(transition, dict)
            or transition.get("applied_at") != applied_at
            or transition.get("batch_sequence_at_application") != 5
            or transition.get("verification_gate_was_clear") is not True
            or transition.get("pending_before") != 1663
            or transition.get("pending_after") != 1659
            or transition.get("excluded_source_ids")
            != sorted(HTML_REDIRECT_EXCLUSION_IDS)
        ):
            raise ImportSafetyError(
                "Checkpoint HTML-redirect transition receipt changed."
            )

    body_phishing_policy = checkpoint.get("body_phishing_security_policy")
    body_phishing_items_by_id: dict[int, dict[str, Any]] = {}
    if body_phishing_policy is not None:
        if html_redirect_policy is None or not isinstance(body_phishing_policy, dict):
            raise ImportSafetyError(
                "Checkpoint body-phishing security policy is invalid."
            )
        body_evidence = load_body_phishing_exclusions(rows)
        body_phishing_items_by_id = {
            int(item["source_id"]): item for item in body_evidence["items"]
        }
        expected_body_policy = {
            "status": "applied",
            "security_exclusion_count": BODY_PHISHING_EXCLUSION_COUNT,
            "security_exclusion_source_ids": sorted(BODY_PHISHING_EXCLUSION_IDS),
            "evidence_manifest": str(BODY_PHISHING_EXCLUSIONS),
            "evidence_manifest_sha256": BODY_PHISHING_EXCLUSIONS_SHA256,
            "original_target_gmail_messages": EXPECTED_TARGET_TOTAL,
            "prior_effective_target_gmail_messages": FINAL_SAFE_TARGET_TOTAL,
            "effective_target_gmail_messages": COMPLETE_SAFE_TARGET_TOTAL,
            "original_new_api_imports": EXPECTED_NEW_IMPORTS,
            "prior_effective_new_api_imports": FINAL_SAFE_NEW_IMPORTS,
            "effective_new_api_imports": COMPLETE_SAFE_NEW_IMPORTS,
            "total_security_exclusion_count": COMPLETE_SECURITY_EXCLUSION_COUNT,
            "source_preservation": "original_eml_unchanged_local_only",
            "gmail_write_policy": "users.messages.import_only_no_scanning_bypass",
        }
        for field, value in expected_body_policy.items():
            if body_phishing_policy.get(field) != value:
                raise ImportSafetyError(
                    f"Checkpoint body-phishing policy field {field} changed."
                )
        applied_at = body_phishing_policy.get("applied_at")
        recovery = body_phishing_policy.get("blocked_batch_recovery")
        recovery_gate = (
            recovery.get("verification_gate_before_recovery")
            if isinstance(recovery, dict)
            else None
        )
        failed_state = (
            recovery.get("failed_source_state_before_recovery")
            if isinstance(recovery, dict)
            else None
        )
        if (
            not isinstance(applied_at, str)
            or not applied_at
            or not isinstance(recovery, dict)
            or recovery.get("batch_sequence") != 6
            or recovery.get("failed_source_id") != 103
            or recovery.get("failed_http_status") != 400
            or recovery.get("gmail_message_id_returned") is not False
            or recovery.get("gate_cleared_at") != applied_at
            or recovery.get("pending_before") != 1634
            or recovery.get("pending_after")
            != 1634 - (BODY_PHISHING_EXCLUSION_COUNT - 1)
            or recovery.get("excluded_pending_count")
            != BODY_PHISHING_EXCLUSION_COUNT - 1
            or not isinstance(recovery_gate, dict)
            or not isinstance(failed_state, dict)
        ):
            raise ImportSafetyError(
                "Checkpoint body-phishing batch-recovery receipt changed."
            )
        if (
            recovery_gate.get("status") != "blocked"
            or recovery_gate.get("batch_sequence") != 6
            or recovery_gate.get("item_keys") != []
            or recovery_gate.get("source_ids") != []
            or len(recovery_gate.get("planned_item_keys", [])) != 250
            or len(set(recovery_gate.get("planned_item_keys", []))) != 250
            or len(recovery_gate.get("planned_source_ids", [])) != 250
            or len(set(recovery_gate.get("planned_source_ids", []))) != 250
            or len(recovery_gate.get("verified_completed_item_keys", [])) != 24
            or len(set(recovery_gate.get("verified_completed_item_keys", []))) != 24
        ):
            raise ImportSafetyError("Checkpoint archived body-phishing gate changed.")
        planned_item_keys = recovery_gate["planned_item_keys"]
        planned_source_ids = recovery_gate["planned_source_ids"]
        if any(item_key not in states for item_key in planned_item_keys) or [
            int(states[item_key]["source_id"]) for item_key in planned_item_keys
        ] != [int(source_id) for source_id in planned_source_ids]:
            raise ImportSafetyError(
                "Checkpoint archived body-phishing gate plan no longer reconciles."
            )
        source_103_item_key = body_phishing_items_by_id[103]["item_key"]
        verified_completed_keys = set(recovery_gate["verified_completed_item_keys"])
        planned_key_set = set(planned_item_keys)
        expected_unattempted_keys = [
            item_key
            for item_key in planned_item_keys
            if item_key not in verified_completed_keys
            and item_key != source_103_item_key
        ]
        body_ids_in_plan = {
            int(states[item_key]["source_id"])
            for item_key in planned_item_keys
            if int(states[item_key]["source_id"]) in BODY_PHISHING_EXCLUSION_IDS
        }
        if (
            source_103_item_key not in planned_key_set
            or source_103_item_key in verified_completed_keys
            or not verified_completed_keys.issubset(planned_key_set)
            or len(expected_unattempted_keys) != 225
            or recovery.get("unattempted_item_keys_at_recovery")
            != expected_unattempted_keys
            or recovery.get("security_exclusion_source_ids_in_blocked_plan")
            != sorted(body_ids_in_plan)
        ):
            raise ImportSafetyError(
                "Checkpoint archived body-phishing recovery partition changed."
            )
        if (
            failed_state.get("source_id") != 103
            or failed_state.get("status") != "failed"
            or failed_state.get("http_status") != 400
            or failed_state.get("gmail_message_id")
            or failed_state.get("error") != SOURCE_103_ERROR
            or failed_state.get("upload_mode") != "resumable_rfc822"
            or failed_state.get("attempted_at") != SOURCE_103_ATTEMPTED_AT
        ):
            raise ImportSafetyError("Archived source 103 failure receipt changed.")
        batch_six_receipts = [
            receipt
            for receipt in checkpoint["verified_batches"]
            if receipt.get("batch_sequence") == 6
        ]
        if (
            len(batch_six_receipts) != 1
            or batch_six_receipts[0].get("item_count") != 24
            or set(batch_six_receipts[0].get("item_keys", []))
            != verified_completed_keys
            or batch_six_receipts[0].get("verified_at")
            != recovery_gate.get("successful_subset_verified_at")
        ):
            raise ImportSafetyError(
                "Archived body-phishing gate does not reconcile with verified batch 6."
            )

    gmail_rejected_attachment_policy = checkpoint.get(
        "gmail_rejected_attachment_policy"
    )
    gmail_rejected_attachment_items_by_id: dict[int, dict[str, Any]] = {}
    if gmail_rejected_attachment_policy is not None:
        if body_phishing_policy is None or not isinstance(
            gmail_rejected_attachment_policy, dict
        ):
            raise ImportSafetyError(
                "Checkpoint Gmail-rejected attachment policy is invalid."
            )
        rejected_evidence = load_gmail_rejected_attachment_exclusions(rows)
        gmail_rejected_attachment_items_by_id = {
            int(item["source_id"]): item for item in rejected_evidence["items"]
        }
        expected_rejected_policy = {
            "status": "applied",
            "gmail_rejected_attachment_count": (
                GMAIL_REJECTED_ATTACHMENT_EXCLUSION_COUNT
            ),
            "gmail_rejected_attachment_source_ids": sorted(
                GMAIL_REJECTED_ATTACHMENT_EXCLUSION_IDS
            ),
            "evidence_manifest": str(GMAIL_REJECTED_ATTACHMENT_EXCLUSIONS),
            "evidence_manifest_sha256": (
                GMAIL_REJECTED_ATTACHMENT_EXCLUSIONS_SHA256
            ),
            "original_target_gmail_messages": EXPECTED_TARGET_TOTAL,
            "prior_effective_target_gmail_messages": COMPLETE_SAFE_TARGET_TOTAL,
            "effective_target_gmail_messages": POST_REJECTION_SAFE_TARGET_TOTAL,
            "original_new_api_imports": EXPECTED_NEW_IMPORTS,
            "prior_effective_new_api_imports": COMPLETE_SAFE_NEW_IMPORTS,
            "effective_new_api_imports": POST_REJECTION_SAFE_NEW_IMPORTS,
            "total_local_only_count": COMPLETE_LOCAL_ONLY_COUNT,
            "source_preservation": "original_eml_unchanged_local_only",
            "gmail_write_policy": "users.messages.import_only_no_scanning_bypass",
            "google_rejection_trigger": "not_independently_known",
        }
        for field, value in expected_rejected_policy.items():
            if gmail_rejected_attachment_policy.get(field) != value:
                raise ImportSafetyError(
                    f"Checkpoint Gmail-rejected policy field {field} changed."
                )
        applied_at = gmail_rejected_attachment_policy.get("applied_at")
        recovery = gmail_rejected_attachment_policy.get("blocked_batch_recovery")
        recovery_gate = (
            recovery.get("verification_gate_before_recovery")
            if isinstance(recovery, dict)
            else None
        )
        failed_state = (
            recovery.get("failed_source_state_before_recovery")
            if isinstance(recovery, dict)
            else None
        )
        if (
            not isinstance(applied_at, str)
            or not applied_at
            or not isinstance(recovery, dict)
            or recovery.get("batch_sequence") != 13
            or recovery.get("failed_source_id") != 1857
            or recovery.get("failed_http_status") != 400
            or recovery.get("gmail_message_id_returned") is not False
            or recovery.get("gate_cleared_at") != applied_at
            or recovery.get("pending_before") != 113
            or recovery.get("pending_after") != 113
            or recovery.get("excluded_pending_count") != 0
            or recovery.get("successful_subset_item_count") != 196
            or recovery.get("pretransition_checkpoint_sha256")
            != SOURCE_1857_PRETRANSITION_CHECKPOINT_SHA256
            or not isinstance(recovery_gate, dict)
            or not isinstance(failed_state, dict)
        ):
            raise ImportSafetyError(
                "Checkpoint Gmail-rejected batch-recovery receipt changed."
            )
        if (
            recovery_gate.get("status") != "blocked"
            or recovery_gate.get("batch_sequence") != 13
            or recovery_gate.get("item_keys") != []
            or recovery_gate.get("source_ids") != []
            or len(recovery_gate.get("planned_item_keys", [])) != 250
            or len(set(recovery_gate.get("planned_item_keys", []))) != 250
            or len(recovery_gate.get("planned_source_ids", [])) != 250
            or len(set(recovery_gate.get("planned_source_ids", []))) != 250
            or len(recovery_gate.get("verified_completed_item_keys", [])) != 196
            or len(set(recovery_gate.get("verified_completed_item_keys", []))) != 196
        ):
            raise ImportSafetyError(
                "Checkpoint archived Gmail-rejected batch-13 gate changed."
            )
        planned_item_keys = recovery_gate["planned_item_keys"]
        planned_source_ids = recovery_gate["planned_source_ids"]
        if any(item_key not in states for item_key in planned_item_keys) or [
            int(states[item_key]["source_id"]) for item_key in planned_item_keys
        ] != [int(source_id) for source_id in planned_source_ids]:
            raise ImportSafetyError(
                "Checkpoint archived Gmail-rejected gate plan no longer reconciles."
            )
        verified_completed_keys = set(recovery_gate["verified_completed_item_keys"])
        expected_unattempted_keys = [
            item_key
            for item_key in planned_item_keys
            if item_key not in verified_completed_keys
            and item_key != SOURCE_1857_ITEM_KEY
        ]
        if (
            SOURCE_1857_ITEM_KEY not in planned_item_keys
            or SOURCE_1857_ITEM_KEY in verified_completed_keys
            or not verified_completed_keys.issubset(set(planned_item_keys))
            or planned_item_keys.index(SOURCE_1857_ITEM_KEY) != 196
            or len(expected_unattempted_keys) != 53
            or recovery.get("unattempted_item_keys_at_recovery")
            != expected_unattempted_keys
        ):
            raise ImportSafetyError(
                "Checkpoint archived Gmail-rejected recovery partition changed."
            )
        if (
            failed_state.get("source_id") != 1857
            or failed_state.get("source_sha256") != SOURCE_1857_ITEM_KEY
            or failed_state.get("message_id") != SOURCE_1857_MESSAGE_ID
            or failed_state.get("status") != "failed"
            or failed_state.get("http_status") != 400
            or failed_state.get("gmail_message_id")
            or failed_state.get("imported_at")
            or failed_state.get("error") != SOURCE_1857_ERROR
            or failed_state.get("upload_mode") != "resumable_rfc822"
            or failed_state.get("attempted_at") != SOURCE_1857_ATTEMPTED_AT
        ):
            raise ImportSafetyError("Archived source 1857 failure receipt changed.")
        batch_thirteen_receipts = [
            receipt
            for receipt in checkpoint["verified_batches"]
            if receipt.get("batch_sequence") == 13
        ]
        if (
            len(batch_thirteen_receipts) != 1
            or batch_thirteen_receipts[0].get("item_count") != 196
            or set(batch_thirteen_receipts[0].get("item_keys", []))
            != verified_completed_keys
            or batch_thirteen_receipts[0].get("verified_at")
            != recovery_gate.get("successful_subset_verified_at")
        ):
            raise ImportSafetyError(
                "Archived Gmail-rejected gate does not reconcile with batch 13."
            )
    gmail_ids = []
    ordinary_verified_keys = set()
    pending_verification_keys = set()
    security_skipped_ids = set()
    html_phishing_skipped_ids = set()
    html_redirect_skipped_ids = set()
    body_phishing_skipped_ids = set()
    gmail_rejected_attachment_skipped_ids = set()
    for row in rows:
        item_key = row["item_key"]
        state = states[item_key]
        for field in ("source_id", "relative_path", "source_sha256", "message_id", "action"):
            if state.get(field) != row.get(field):
                raise ImportSafetyError(
                    f"Checkpoint row drift at source {row['source_id']} field {field}."
                )
        status = state.get("status")
        if row["action"] == "already_imported_verified_pilot":
            if status != "verified_pilot" or state.get("gmail_message_id") != row.get(
                "gmail_message_id"
            ):
                raise ImportSafetyError("A verified pilot checkpoint row changed.")
        elif row["action"] == "skip_semantic_duplicate":
            if status != "skipped_semantic_duplicate":
                raise ImportSafetyError("A semantic-duplicate skip row changed.")
            if state.get("gmail_message_id"):
                raise ImportSafetyError("A skipped duplicate unexpectedly has a Gmail ID.")
        else:
            if status not in {
                "pending",
                "inflight",
                "imported_pending_verification",
                "verified",
                "uncertain",
                "failed",
                "review_required",
                "skipped_security_attachment",
                "skipped_security_html_phishing",
                "skipped_security_html_redirect",
                "skipped_security_body_phishing",
                "skipped_gmail_rejected_attachment",
            }:
                raise ImportSafetyError(
                    f"Unknown status {status} for source {row['source_id']}."
                )
            if status == "pending":
                if any(
                    state.get(field)
                    for field in (
                        "gmail_message_id",
                        "attempted_at",
                        "imported_at",
                        "verified_manually_at",
                    )
                ):
                    raise ImportSafetyError(
                        f"Pending source {row['source_id']} contains execution receipts."
                    )
            elif status == "inflight":
                if not state.get("attempted_at") or state.get("gmail_message_id"):
                    raise ImportSafetyError(
                        f"Inflight source {row['source_id']} has invalid receipt fields."
                    )
            elif status in {"imported_pending_verification", "verified"}:
                if not state.get("gmail_message_id") or not state.get("imported_at"):
                    raise ImportSafetyError(
                        f"Imported source {row['source_id']} lacks its Gmail receipt."
                    )
                if status == "imported_pending_verification":
                    pending_verification_keys.add(item_key)
                else:
                    if not state.get("verified_manually_at"):
                        raise ImportSafetyError(
                            f"Verified source {row['source_id']} lacks verification time."
                        )
                    ordinary_verified_keys.add(item_key)
            elif status == "skipped_security_attachment":
                source_id = int(row["source_id"])
                security_skipped_ids.add(source_id)
                if source_id not in SECURITY_EXCLUSION_IDS or security_policy is None:
                    raise ImportSafetyError(
                        f"Source {source_id} has an unauthorized security skip."
                    )
                evidence = security_items_by_id[source_id]
                expected_security_state = {
                    "security_excluded_at": security_policy["applied_at"],
                    "security_exclusion_manifest": str(SECURITY_EXCLUSIONS),
                    "security_exclusion_manifest_sha256": SECURITY_EXCLUSIONS_SHA256,
                    "security_classification": evidence["classification"],
                    "archive_magic": evidence["archive_magic"],
                    "attachment_filename": evidence["attachment_filename"],
                    "attachment_content_type": evidence["attachment_content_type"],
                    "attachment_size_bytes": evidence["attachment_size_bytes"],
                    "attachment_sha256": evidence["attachment_sha256"],
                    "blocked_members": evidence["blocked_members"],
                    "source_preservation": evidence["source_preservation"],
                    "source_preserved_path": str(SOURCE_ROOT / row["relative_path"]),
                    "source_preserved_sha256": row["source_sha256"],
                    "gmail_write_attempted": source_id == 65,
                    "gmail_outcome": (
                        "definite_rejection_no_message_id"
                        if source_id == 65
                        else "not_attempted"
                    ),
                    "status_before_security_exclusion": (
                        "failed" if source_id == 65 else "pending"
                    ),
                }
                for field, value in expected_security_state.items():
                    if state.get(field) != value:
                        raise ImportSafetyError(
                            f"Security-excluded source {source_id} field {field} changed."
                        )
                if any(
                    state.get(field)
                    for field in (
                        "gmail_message_id",
                        "imported_at",
                        "verified_manually_at",
                        "manual_verification_required",
                    )
                ):
                    raise ImportSafetyError(
                        f"Security-excluded source {source_id} has a Gmail receipt."
                    )
                if source_id == 65:
                    if (
                        state.get("http_status") != 400
                        or state.get("error") != SOURCE_65_ERROR
                        or state.get("upload_mode") != "resumable_rfc822"
                        or state.get("attempted_at") != SOURCE_65_ATTEMPTED_AT
                    ):
                        raise ImportSafetyError(
                            "Security-excluded source 65 lost its rejection receipt."
                        )
                elif any(
                    state.get(field)
                    for field in (
                        "attempted_at",
                        "http_status",
                        "error",
                        "error_type",
                        "error_phase",
                        "upload_mode",
                    )
                ):
                    raise ImportSafetyError(
                        f"Unattempted security exclusion {source_id} has execution receipts."
                    )
            elif status == "skipped_security_html_phishing":
                source_id = int(row["source_id"])
                html_phishing_skipped_ids.add(source_id)
                if (
                    source_id not in HTML_PHISHING_EXCLUSION_IDS
                    or html_phishing_policy is None
                ):
                    raise ImportSafetyError(
                        f"Source {source_id} has an unauthorized HTML-phishing skip."
                    )
                evidence = html_phishing_items_by_id[source_id]
                expected_html_state = {
                    "security_excluded_at": html_phishing_policy["applied_at"],
                    "security_exclusion_manifest": str(HTML_PHISHING_EXCLUSIONS),
                    "security_exclusion_manifest_sha256": (
                        HTML_PHISHING_EXCLUSIONS_SHA256
                    ),
                    "security_classification": evidence["classification"],
                    "security_indicators": evidence["indicators"],
                    "attachment_filename": evidence["attachment_filename"],
                    "attachment_content_type": evidence["attachment_content_type"],
                    "attachment_size_bytes": evidence["attachment_size_bytes"],
                    "attachment_sha256": evidence["attachment_sha256"],
                    "source_preservation": evidence["source_preservation"],
                    "source_preserved_path": str(SOURCE_ROOT / row["relative_path"]),
                    "source_preserved_sha256": row["source_sha256"],
                    "gmail_write_attempted": source_id == 74,
                    "gmail_outcome": evidence["gmail_outcome_at_detection"],
                    "status_before_security_exclusion": (
                        "failed" if source_id == 74 else "pending"
                    ),
                }
                for field, value in expected_html_state.items():
                    if state.get(field) != value:
                        raise ImportSafetyError(
                            f"HTML-phishing source {source_id} field {field} changed."
                        )
                if any(
                    state.get(field)
                    for field in (
                        "gmail_message_id",
                        "imported_at",
                        "verified_manually_at",
                        "manual_verification_required",
                    )
                ):
                    raise ImportSafetyError(
                        f"HTML-phishing source {source_id} has a Gmail receipt."
                    )
                if source_id == 74:
                    if (
                        state.get("http_status") != 400
                        or state.get("error") != SOURCE_74_ERROR
                        or state.get("upload_mode") != "resumable_rfc822"
                        or state.get("attempted_at") != SOURCE_74_ATTEMPTED_AT
                    ):
                        raise ImportSafetyError(
                            "HTML-phishing source 74 lost its rejection receipt."
                        )
                elif any(
                    state.get(field)
                    for field in (
                        "attempted_at",
                        "http_status",
                        "error",
                        "error_type",
                        "error_phase",
                        "upload_mode",
                    )
                ):
                    raise ImportSafetyError(
                        f"Unattempted HTML-phishing exclusion {source_id} has receipts."
                    )
            elif status == "skipped_security_html_redirect":
                source_id = int(row["source_id"])
                html_redirect_skipped_ids.add(source_id)
                if (
                    source_id not in HTML_REDIRECT_EXCLUSION_IDS
                    or html_redirect_policy is None
                ):
                    raise ImportSafetyError(
                        f"Source {source_id} has an unauthorized HTML-redirect skip."
                    )
                evidence = html_redirect_items_by_id[source_id]
                expected_redirect_state = {
                    "security_excluded_at": html_redirect_policy["applied_at"],
                    "security_exclusion_manifest": str(HTML_REDIRECT_EXCLUSIONS),
                    "security_exclusion_manifest_sha256": (
                        HTML_REDIRECT_EXCLUSIONS_SHA256
                    ),
                    "security_classification": evidence["classification"],
                    "security_indicators": evidence["indicators"],
                    "attachment_filename": evidence["attachment_filename"],
                    "attachment_content_type": evidence["attachment_content_type"],
                    "attachment_size_bytes": evidence["attachment_size_bytes"],
                    "attachment_sha256": evidence["attachment_sha256"],
                    "source_preservation": evidence["source_preservation"],
                    "source_preserved_path": str(SOURCE_ROOT / row["relative_path"]),
                    "source_preserved_sha256": row["source_sha256"],
                    "gmail_write_attempted": False,
                    "gmail_outcome": evidence["gmail_outcome_at_detection"],
                    "status_before_security_exclusion": "pending",
                }
                for field, value in expected_redirect_state.items():
                    if state.get(field) != value:
                        raise ImportSafetyError(
                            f"HTML-redirect source {source_id} field {field} changed."
                        )
                if any(
                    state.get(field)
                    for field in (
                        "gmail_message_id",
                        "attempted_at",
                        "imported_at",
                        "verified_manually_at",
                        "manual_verification_required",
                        "http_status",
                        "error",
                        "error_type",
                        "error_phase",
                        "upload_mode",
                    )
                ):
                    raise ImportSafetyError(
                        f"HTML-redirect exclusion {source_id} has execution receipts."
                    )
            elif status == "skipped_security_body_phishing":
                source_id = int(row["source_id"])
                body_phishing_skipped_ids.add(source_id)
                if (
                    source_id not in BODY_PHISHING_EXCLUSION_IDS
                    or body_phishing_policy is None
                ):
                    raise ImportSafetyError(
                        f"Source {source_id} has an unauthorized body-phishing skip."
                    )
                evidence = body_phishing_items_by_id[source_id]
                expected_body_state = {
                    "security_excluded_at": body_phishing_policy["applied_at"],
                    "security_exclusion_manifest": str(BODY_PHISHING_EXCLUSIONS),
                    "security_exclusion_manifest_sha256": (
                        BODY_PHISHING_EXCLUSIONS_SHA256
                    ),
                    "security_classification": evidence["classification"],
                    "security_indicators": evidence["indicators"],
                    "body_content_type": evidence["body_content_type"],
                    "body_part_index": evidence["body_part_index"],
                    "body_size_bytes": evidence["body_size_bytes"],
                    "body_sha256": evidence["body_sha256"],
                    "link_hosts": evidence["link_hosts"],
                    "source_preservation": evidence["source_preservation"],
                    "source_preserved_path": str(SOURCE_ROOT / row["relative_path"]),
                    "source_preserved_sha256": row["source_sha256"],
                    "gmail_write_attempted": source_id == 103,
                    "gmail_outcome": evidence["gmail_outcome_at_detection"],
                    "status_before_security_exclusion": (
                        "failed" if source_id == 103 else "pending"
                    ),
                }
                for field, value in expected_body_state.items():
                    if state.get(field) != value:
                        raise ImportSafetyError(
                            f"Body-phishing source {source_id} field {field} changed."
                        )
                if any(
                    state.get(field)
                    for field in (
                        "gmail_message_id",
                        "imported_at",
                        "verified_manually_at",
                        "manual_verification_required",
                    )
                ):
                    raise ImportSafetyError(
                        f"Body-phishing source {source_id} has a Gmail receipt."
                    )
                if source_id == 103:
                    if (
                        state.get("http_status") != 400
                        or state.get("error") != SOURCE_103_ERROR
                        or state.get("upload_mode") != "resumable_rfc822"
                        or state.get("attempted_at") != SOURCE_103_ATTEMPTED_AT
                    ):
                        raise ImportSafetyError(
                            "Body-phishing source 103 lost its rejection receipt."
                        )
                elif any(
                    state.get(field)
                    for field in (
                        "attempted_at",
                        "http_status",
                        "error",
                        "error_type",
                        "error_phase",
                        "upload_mode",
                    )
                ):
                    raise ImportSafetyError(
                        f"Unattempted body-phishing exclusion {source_id} has receipts."
                    )
            elif status == "skipped_gmail_rejected_attachment":
                source_id = int(row["source_id"])
                gmail_rejected_attachment_skipped_ids.add(source_id)
                if (
                    source_id not in GMAIL_REJECTED_ATTACHMENT_EXCLUSION_IDS
                    or gmail_rejected_attachment_policy is None
                ):
                    raise ImportSafetyError(
                        f"Source {source_id} has an unauthorized Gmail-rejected skip."
                    )
                evidence = gmail_rejected_attachment_items_by_id[source_id]
                expected_rejected_state = {
                    "security_excluded_at": (
                        gmail_rejected_attachment_policy["applied_at"]
                    ),
                    "security_exclusion_manifest": str(
                        GMAIL_REJECTED_ATTACHMENT_EXCLUSIONS
                    ),
                    "security_exclusion_manifest_sha256": (
                        GMAIL_REJECTED_ATTACHMENT_EXCLUSIONS_SHA256
                    ),
                    "security_classification": evidence["classification"],
                    "security_indicators": evidence["indicators"],
                    "attachment_part_index": evidence["attachment_part_index"],
                    "attachment_filename": evidence["attachment_filename"],
                    "attachment_content_type": evidence["attachment_content_type"],
                    "attachment_size_bytes": evidence["attachment_size_bytes"],
                    "attachment_sha256": evidence["attachment_sha256"],
                    "source_preservation": evidence["source_preservation"],
                    "source_preserved_path": str(SOURCE_ROOT / row["relative_path"]),
                    "source_preserved_sha256": row["source_sha256"],
                    "gmail_write_attempted": True,
                    "gmail_outcome": evidence["gmail_outcome_at_detection"],
                    "status_before_security_exclusion": "failed",
                }
                for field, value in expected_rejected_state.items():
                    if state.get(field) != value:
                        raise ImportSafetyError(
                            f"Gmail-rejected source {source_id} field {field} changed."
                        )
                if any(
                    state.get(field)
                    for field in (
                        "gmail_message_id",
                        "imported_at",
                        "verified_manually_at",
                        "manual_verification_required",
                    )
                ):
                    raise ImportSafetyError(
                        f"Gmail-rejected source {source_id} has a Gmail receipt."
                    )
                if (
                    state.get("http_status") != 400
                    or state.get("error") != SOURCE_1857_ERROR
                    or state.get("upload_mode") != "resumable_rfc822"
                    or state.get("attempted_at") != SOURCE_1857_ATTEMPTED_AT
                ):
                    raise ImportSafetyError(
                        "Gmail-rejected source 1857 lost its rejection receipt."
                    )
        if state.get("gmail_message_id"):
            gmail_ids.append(str(state["gmail_message_id"]))
    if security_policy is None and security_skipped_ids:
        raise ImportSafetyError("Security skips exist without their checkpoint policy.")
    if security_policy is not None and security_skipped_ids != SECURITY_EXCLUSION_IDS:
        raise ImportSafetyError("Checkpoint security skips do not cover the exact 20 rows.")
    if html_phishing_policy is None and html_phishing_skipped_ids:
        raise ImportSafetyError(
            "HTML-phishing skips exist without their checkpoint policy."
        )
    if (
        html_phishing_policy is not None
        and html_phishing_skipped_ids != HTML_PHISHING_EXCLUSION_IDS
    ):
        raise ImportSafetyError(
            "Checkpoint HTML-phishing skips do not cover the exact 14 rows."
        )
    if html_redirect_policy is None and html_redirect_skipped_ids:
        raise ImportSafetyError(
            "HTML-redirect skips exist without their checkpoint policy."
        )
    if (
        html_redirect_policy is not None
        and html_redirect_skipped_ids != HTML_REDIRECT_EXCLUSION_IDS
    ):
        raise ImportSafetyError(
            "Checkpoint HTML-redirect skips do not cover the exact four rows."
        )
    if body_phishing_policy is None and body_phishing_skipped_ids:
        raise ImportSafetyError(
            "Body-phishing skips exist without their checkpoint policy."
        )
    if (
        body_phishing_policy is not None
        and body_phishing_skipped_ids != BODY_PHISHING_EXCLUSION_IDS
    ):
        raise ImportSafetyError(
            "Checkpoint body-phishing skips do not cover the exact evidence rows."
        )
    if (
        gmail_rejected_attachment_policy is None
        and gmail_rejected_attachment_skipped_ids
    ):
        raise ImportSafetyError(
            "Gmail-rejected attachment skips exist without their checkpoint policy."
        )
    if (
        gmail_rejected_attachment_policy is not None
        and gmail_rejected_attachment_skipped_ids
        != GMAIL_REJECTED_ATTACHMENT_EXCLUSION_IDS
    ):
        raise ImportSafetyError(
            "Checkpoint Gmail-rejected skips do not cover the exact evidence row."
        )
    if security_policy is not None:
        action_counts = Counter(str(row.get("action")) for row in rows)
        if action_counts != Counter(
            {
                "import": EXPECTED_NEW_IMPORTS,
                "already_imported_verified_pilot": 5,
                "skip_semantic_duplicate": 3,
            }
        ):
            raise ImportSafetyError(
                "Manifest arithmetic changed after applying security exclusions."
            )
        effective_import_rows = [
            row
            for row in rows
            if row.get("action") == "import"
            and int(row["source_id"]) not in SECURITY_EXCLUSION_IDS
        ]
        if (
            len(effective_import_rows) != EFFECTIVE_NEW_IMPORTS
            or 5 + EFFECTIVE_NEW_IMPORTS != EFFECTIVE_TARGET_TOTAL
            or 5 + 3 + SECURITY_EXCLUSION_COUNT + EFFECTIVE_NEW_IMPORTS
            != SOURCE_COUNT
        ):
            raise ImportSafetyError(
                "Effective Gmail target arithmetic no longer reconciles."
            )
    if html_phishing_policy is not None:
        safe_import_rows = [
            row
            for row in rows
            if row.get("action") == "import"
            and int(row["source_id"])
            not in SECURITY_EXCLUSION_IDS | HTML_PHISHING_EXCLUSION_IDS
        ]
        if (
            len(safe_import_rows) != SAFE_NEW_IMPORTS_AFTER_HTML_EXCLUSIONS
            or 5 + SAFE_NEW_IMPORTS_AFTER_HTML_EXCLUSIONS
            != SAFE_TARGET_TOTAL_AFTER_HTML_EXCLUSIONS
            or 5
            + 3
            + TOTAL_SECURITY_EXCLUSION_COUNT
            + SAFE_NEW_IMPORTS_AFTER_HTML_EXCLUSIONS
            != SOURCE_COUNT
        ):
            raise ImportSafetyError(
                "HTML-phishing safe-target arithmetic no longer reconciles."
            )
    if html_redirect_policy is not None:
        final_safe_import_rows = [
            row
            for row in rows
            if row.get("action") == "import"
            and int(row["source_id"])
            not in (
                SECURITY_EXCLUSION_IDS
                | HTML_PHISHING_EXCLUSION_IDS
                | HTML_REDIRECT_EXCLUSION_IDS
            )
        ]
        if (
            len(final_safe_import_rows) != FINAL_SAFE_NEW_IMPORTS
            or 5 + FINAL_SAFE_NEW_IMPORTS != FINAL_SAFE_TARGET_TOTAL
            or 5
            + 3
            + FINAL_SECURITY_EXCLUSION_COUNT
            + FINAL_SAFE_NEW_IMPORTS
            != SOURCE_COUNT
        ):
            raise ImportSafetyError(
                "Final security-filtered target arithmetic no longer reconciles."
            )
    if body_phishing_policy is not None:
        complete_safe_import_rows = [
            row
            for row in rows
            if row.get("action") == "import"
            and int(row["source_id"])
            not in (
                SECURITY_EXCLUSION_IDS
                | HTML_PHISHING_EXCLUSION_IDS
                | HTML_REDIRECT_EXCLUSION_IDS
                | BODY_PHISHING_EXCLUSION_IDS
            )
        ]
        if (
            len(complete_safe_import_rows) != COMPLETE_SAFE_NEW_IMPORTS
            or 5 + COMPLETE_SAFE_NEW_IMPORTS != COMPLETE_SAFE_TARGET_TOTAL
            or 5
            + 3
            + COMPLETE_SECURITY_EXCLUSION_COUNT
            + COMPLETE_SAFE_NEW_IMPORTS
            != SOURCE_COUNT
        ):
            raise ImportSafetyError(
                "Body-phishing filtered target arithmetic no longer reconciles."
            )
    if gmail_rejected_attachment_policy is not None:
        post_rejection_safe_import_rows = [
            row
            for row in rows
            if row.get("action") == "import"
            and int(row["source_id"])
            not in (
                SECURITY_EXCLUSION_IDS
                | HTML_PHISHING_EXCLUSION_IDS
                | HTML_REDIRECT_EXCLUSION_IDS
                | BODY_PHISHING_EXCLUSION_IDS
                | GMAIL_REJECTED_ATTACHMENT_EXCLUSION_IDS
            )
        ]
        if (
            len(post_rejection_safe_import_rows) != POST_REJECTION_SAFE_NEW_IMPORTS
            or 5 + POST_REJECTION_SAFE_NEW_IMPORTS
            != POST_REJECTION_SAFE_TARGET_TOTAL
            or 5
            + 3
            + COMPLETE_LOCAL_ONLY_COUNT
            + POST_REJECTION_SAFE_NEW_IMPORTS
            != SOURCE_COUNT
        ):
            raise ImportSafetyError(
                "Gmail-rejected attachment target arithmetic no longer reconciles."
            )
    if len(gmail_ids) != len(set(gmail_ids)):
        raise ImportSafetyError("Checkpoint contains a repeated Gmail message ID.")

    verified_batch_keys = []
    verified_batch_sequences = []
    for receipt in checkpoint["verified_batches"]:
        if not isinstance(receipt, dict):
            raise ImportSafetyError("A verified-batch receipt is not an object.")
        sequence = receipt.get("batch_sequence")
        item_keys = receipt.get("item_keys")
        receipt_ids = receipt.get("gmail_message_ids")
        if (
            not isinstance(sequence, int)
            or not isinstance(item_keys, list)
            or not item_keys
            or len(item_keys) != len(set(item_keys))
            or receipt.get("item_count") != len(item_keys)
            or not isinstance(receipt_ids, dict)
            or set(receipt_ids) != set(item_keys)
        ):
            raise ImportSafetyError("A verified-batch receipt is structurally invalid.")
        verified_batch_sequences.append(sequence)
        for item_key in item_keys:
            if item_key not in states or states[item_key].get("status") != "verified":
                raise ImportSafetyError(
                    "A verified-batch receipt references a non-verified row."
                )
            if receipt_ids[item_key] != states[item_key].get("gmail_message_id"):
                raise ImportSafetyError("A verified-batch Gmail ID does not match its row.")
            verified_batch_keys.append(item_key)
    if len(verified_batch_keys) != len(set(verified_batch_keys)):
        raise ImportSafetyError("A row appears in more than one verified-batch receipt.")
    if set(verified_batch_keys) != ordinary_verified_keys:
        raise ImportSafetyError("Verified rows and verified-batch receipts do not reconcile.")
    if len(verified_batch_sequences) != len(set(verified_batch_sequences)):
        raise ImportSafetyError("Verified-batch sequence numbers are repeated.")

    gate = checkpoint.get("verification_gate")
    if gate is not None:
        if not isinstance(gate, dict) or gate.get("status") not in {
            "collecting",
            "required",
            "blocked",
        }:
            raise ImportSafetyError("Checkpoint verification gate is invalid.")
        item_keys = gate.get("item_keys")
        planned_item_keys = gate.get("planned_item_keys")
        if (
            not isinstance(item_keys, list)
            or len(item_keys) != len(set(item_keys))
            or not isinstance(planned_item_keys, list)
            or not planned_item_keys
            or len(planned_item_keys) != len(set(planned_item_keys))
            or not set(item_keys).issubset(planned_item_keys)
        ):
            raise ImportSafetyError("Checkpoint verification gate batch rows are invalid.")
        if not set(item_keys).issubset(states):
            raise ImportSafetyError("Checkpoint verification gate references unknown rows.")
        if not set(planned_item_keys).issubset(states):
            raise ImportSafetyError("Checkpoint gate plan references unknown rows.")
        if set(item_keys) != pending_verification_keys:
            raise ImportSafetyError(
                "Checkpoint verification gate does not cover every unverified import."
            )
        for item_key in item_keys:
            if states[item_key].get("status") != "imported_pending_verification":
                raise ImportSafetyError(
                    "Checkpoint verification gate row is not pending verification."
                )
        if gate.get("batch_sequence") != checkpoint["batch_sequence"]:
            raise ImportSafetyError("Checkpoint gate sequence does not match batch_sequence.")
    elif pending_verification_keys:
        raise ImportSafetyError(
            "Checkpoint has imported rows awaiting verification but no verification gate."
        )
    recorded_sequences = verified_batch_sequences + (
        [int(gate["batch_sequence"])] if gate is not None else []
    )
    if recorded_sequences and max(recorded_sequences) != checkpoint["batch_sequence"]:
        raise ImportSafetyError("Checkpoint batch sequence does not reconcile.")
    if not recorded_sequences and checkpoint["batch_sequence"] != 0:
        raise ImportSafetyError("Checkpoint has a batch sequence without any batch record.")
    return checkpoint


def blocking_states(checkpoint: dict[str, Any]) -> list[tuple[int, str]]:
    blocked = []
    for state in checkpoint["states"].values():
        if state.get("status") in {
            "inflight",
            "uncertain",
            "failed",
            "review_required",
        }:
            blocked.append((int(state["source_id"]), str(state["status"])))
    return sorted(blocked)


def status_counts(checkpoint: dict[str, Any]) -> Counter:
    return Counter(str(state.get("status")) for state in checkpoint["states"].values())


def recover_empty_collecting_gate(
    checkpoint_path: Path, checkpoint: dict[str, Any]
) -> bool:
    """Clear a batch reservation only when no request could have started."""
    gate = checkpoint.get("verification_gate")
    if not isinstance(gate, dict) or gate.get("status") != "collecting":
        return False
    if gate.get("item_keys"):
        return False
    planned = gate.get("planned_item_keys", [])
    if not planned or any(
        checkpoint["states"][item_key].get("status") != "pending"
        for item_key in planned
    ):
        return False
    prior_sequences = [
        int(receipt["batch_sequence"])
        for receipt in checkpoint.get("verified_batches", [])
    ]
    checkpoint["batch_sequence"] = max(prior_sequences, default=0)
    checkpoint["verification_gate"] = None
    checkpoint["updated_at"] = utc_now()
    write_json_atomic(checkpoint_path, checkpoint)
    print("recovered_empty_batch_reservation: true")
    return True


def required_validation_batch_size(
    checkpoint: dict[str, Any], rows: list[dict]
) -> int | None:
    """Keep the first 25 canary rows isolated until all are verified."""
    rows_by_key = {row["item_key"]: row for row in rows}
    first_keys = {
        row["item_key"]
        for row in rows
        if row.get("action") == "import" and int(row["import_order"]) <= 25
    }
    states = checkpoint["states"]
    if all(states[item_key].get("status") == "verified" for item_key in first_keys):
        return None
    pending_first = {
        item_key for item_key in first_keys if states[item_key].get("status") == "pending"
    }
    unexpected_first = {
        item_key
        for item_key in first_keys
        if states[item_key].get("status") not in {"pending", "verified"}
    }
    if unexpected_first:
        raise ImportSafetyError(
            "The 25-message validation set contains unresolved nonterminal states."
        )
    touched_later = [
        int(rows_by_key[item_key]["source_id"])
        for item_key, state in states.items()
        if rows_by_key[item_key].get("action") == "import"
        and int(rows_by_key[item_key]["import_order"]) > 25
        and state.get("status") != "pending"
    ]
    if touched_later:
        raise ImportSafetyError(
            "Later archive rows were touched before the validation set completed."
        )
    if not pending_first:
        raise ImportSafetyError(
            "The validation set is incomplete but has no safely pending rows."
        )
    return len(pending_first)


@contextmanager
def exclusive_checkpoint_lock(checkpoint_path: Path):
    lock_path = checkpoint_path.with_name(checkpoint_path.name + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+", encoding="utf-8") as handle:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ImportSafetyError("Another full-import process is running.") from exc
        handle.seek(0)
        handle.truncate()
        handle.write(f"pid={os.getpid()} locked_at={utc_now()}\n")
        handle.flush()
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def granted_scopes(flow: InstalledAppFlow) -> set[str]:
    value = flow.oauth2session.token.get("scope", ())
    if isinstance(value, str):
        return set(value.split())
    return {str(item) for item in value}


def authorize(credentials_path: Path):
    flow = InstalledAppFlow.from_client_secrets_file(
        str(credentials_path), scopes=SCOPES
    )
    flow.run_local_server(
        port=0,
        open_browser=True,
        prompt="select_account",
        login_hint=DESTINATION,
        access_type="online",
        authorization_prompt_message="AUTH_URL: {url}",
        success_message=(
            "OAuth finished. Return to Terminal; the full importer will verify the "
            "exact account before making this bounded batch."
        ),
    )
    if not set(SCOPES).issubset(granted_scopes(flow)):
        raise ImportSafetyError("Google did not grant all required scopes.")
    request = Request(
        "https://openidconnect.googleapis.com/v1/userinfo",
        headers={"Authorization": "Bearer " + flow.credentials.token},
    )
    try:
        with urlopen(request, timeout=15) as response:
            user = json.load(response)
    except Exception as exc:
        raise ImportSafetyError("Could not verify the authorized Google account.") from exc
    actual = str(user.get("email", "")).strip().lower()
    if actual != DESTINATION:
        raise ImportSafetyError(
            f"Authorized account is {actual or '(unavailable)'}, expected {DESTINATION}."
        )
    return flow.credentials


def save_state(
    checkpoint_path: Path,
    checkpoint: dict[str, Any],
    item_key: str,
    **updates: Any,
) -> None:
    checkpoint["states"][item_key].update(updates)
    checkpoint["updated_at"] = utc_now()
    write_json_atomic(checkpoint_path, checkpoint)


@contextmanager
def upload_path_for(row: dict, checkpoint_path: Path):
    source_path = SOURCE_ROOT / row["relative_path"]
    raw = source_path.read_bytes()
    if sha256_bytes(raw) != row["source_sha256"]:
        raise ImportSafetyError(f"Source {row['source_id']} changed before upload.")
    prepared, repairs = normalize_eml(raw, int(row["source_id"]))
    if repairs != row["repairs"] or sha256_bytes(prepared) != row["prepared_sha256"]:
        raise ImportSafetyError(f"Prepared source {row['source_id']} no longer matches.")
    if not repairs:
        yield source_path
        return
    staging_dir = checkpoint_path.parent / "staging"
    staging_dir.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        mode="wb",
        prefix=f"source-{row['source_id']}-",
        suffix=".eml",
        dir=staging_dir,
        delete=False,
    )
    temporary_path = Path(handle.name)
    try:
        with handle:
            handle.write(prepared)
            handle.flush()
            os.fsync(handle.fileno())
        if sha256_file(temporary_path) != row["prepared_sha256"]:
            raise ImportSafetyError(f"Staged source {row['source_id']} hash mismatch.")
        yield temporary_path
    finally:
        temporary_path.unlink(missing_ok=True)


def write_batch_searches(rows: list[dict]) -> None:
    lines = [
        'mailbox most recent full-import batch verification searches',
        'Destination: example-b54b38f4@example.org',
        "Each query should return exactly one Inbox result after this batch.",
        "",
    ]
    for row in rows:
        lines.append(
            f"source {row['source_id']}: in:inbox rfc822msgid:{row['message_id']}"
        )
    LAST_BATCH_SEARCHES.write_text("\n".join(lines) + "\n", encoding="utf-8")


def import_batch(
    credentials,
    rows: list[dict],
    checkpoint_path: Path,
    checkpoint: dict[str, Any],
    batch_size: int,
) -> int:
    rows_by_key = {row["item_key"]: row for row in rows}
    pending = sorted(
        (
            rows_by_key[key]
            for key, state in checkpoint["states"].items()
            if state.get("status") == "pending"
        ),
        key=lambda row: int(row["import_order"]),
    )
    selected = pending[:batch_size]
    if not selected:
        print("No pending messages remain.")
        return 0
    service = build("gmail", "v1", credentials=credentials, cache_discovery=False)
    existing_ids = {
        str(state["gmail_message_id"])
        for state in checkpoint["states"].values()
        if state.get("gmail_message_id")
    }
    completed_rows = []
    batch_sequence = int(checkpoint.get("batch_sequence", 0)) + 1
    checkpoint["batch_sequence"] = batch_sequence
    checkpoint["verification_gate"] = {
        "status": "collecting",
        "batch_sequence": batch_sequence,
        "created_at": utc_now(),
        "planned_item_keys": [row["item_key"] for row in selected],
        "planned_source_ids": [row["source_id"] for row in selected],
        "item_keys": [],
        "source_ids": [],
        "search_file": str(LAST_BATCH_SEARCHES),
    }
    checkpoint["updated_at"] = utc_now()
    write_json_atomic(checkpoint_path, checkpoint)
    for row in selected:
        item_key = row["item_key"]
        request_started = False
        try:
            with upload_path_for(row, checkpoint_path) as upload_path:
                media = MediaFileUpload(
                    str(upload_path), mimetype="message/rfc822", resumable=True
                )
                request = (
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
                        fields="id",
                    )
                )
                # Construct the request before marking the row inflight.  In
                # Python 3.14, googleapiclient's non-resumable multipart builder
                # can raise UnicodeEncodeError locally for a valid RFC822 message
                # containing raw UTF-8 MIME parameters.  A resumable upload sends
                # the metadata first and streams the original message bytes, so
                # it does not reserialize the RFC822 payload.
                save_state(
                    checkpoint_path,
                    checkpoint,
                    item_key,
                    status="inflight",
                    attempted_at=utc_now(),
                    upload_mode="resumable_rfc822",
                )
                request_started = True
                result = request.execute(num_retries=0)
        except HttpError as exc:
            status_code = int(getattr(exc.resp, "status", 0) or 0)
            definite_failure = 400 <= status_code < 500 and status_code not in {
                408,
                409,
                425,
                429,
            }
            final_status = "failed" if definite_failure else "uncertain"
            reason = exc._get_reason() if hasattr(exc, "_get_reason") else "API error"
            checkpoint["states"][item_key].update(
                status=final_status,
                http_status=status_code,
                error=str(reason)[:500],
            )
            checkpoint["verification_gate"]["status"] = "blocked"
            checkpoint["updated_at"] = utc_now()
            write_json_atomic(checkpoint_path, checkpoint)
            write_batch_searches(completed_rows)
            print(
                f"source {row['source_id']}: {final_status}; stopped before the next message.",
                file=sys.stderr,
            )
            return 4
        except Exception as exc:
            final_status = "uncertain" if request_started else "failed"
            checkpoint["states"][item_key].update(
                status=final_status,
                error_type=type(exc).__name__,
                error_phase=("request_execution" if request_started else "preflight"),
            )
            checkpoint["verification_gate"]["status"] = "blocked"
            checkpoint["updated_at"] = utc_now()
            write_json_atomic(checkpoint_path, checkpoint)
            write_batch_searches(completed_rows)
            print(
                f"source {row['source_id']}: {final_status} after "
                f"{type(exc).__name__}; stopped.",
                file=sys.stderr,
            )
            return 4

        gmail_id = str(result.get("id", ""))
        if not gmail_id or gmail_id in existing_ids:
            checkpoint["states"][item_key].update(
                status="review_required",
                error=(
                    "API response lacked a Gmail ID"
                    if not gmail_id
                    else "API returned a Gmail ID already present in the checkpoint"
                ),
            )
            checkpoint["verification_gate"]["status"] = "blocked"
            checkpoint["updated_at"] = utc_now()
            write_json_atomic(checkpoint_path, checkpoint)
            write_batch_searches(completed_rows)
            print(f"source {row['source_id']}: review required; stopped.", file=sys.stderr)
            return 4
        existing_ids.add(gmail_id)
        checkpoint["states"][item_key].update(
            status="imported_pending_verification",
            imported_at=utc_now(),
            gmail_message_id=gmail_id,
            manual_verification_required=True,
        )
        checkpoint["verification_gate"]["item_keys"].append(item_key)
        checkpoint["verification_gate"]["source_ids"].append(row["source_id"])
        checkpoint["updated_at"] = utc_now()
        write_json_atomic(checkpoint_path, checkpoint)
        completed_rows.append(row)
        write_batch_searches(completed_rows)
        print(f"source {row['source_id']}: imported; Gmail message ID {gmail_id}")

    checkpoint["verification_gate"]["status"] = "required"
    checkpoint["verification_gate"]["completed_at"] = utc_now()
    checkpoint["updated_at"] = utc_now()
    write_json_atomic(checkpoint_path, checkpoint)
    counts = status_counts(checkpoint)
    print("authorized_destination:", DESTINATION)
    print("imported_this_batch:", len(completed_rows))
    print("pending_new_imports:", counts.get("pending", 0))
    print(
        "imported_pending_verification:",
        counts.get("imported_pending_verification", 0),
    )
    return 0


def record_last_batch_verified(
    checkpoint_path: Path,
    checkpoint: dict[str, Any],
    verification_method: str = "gmail_ui_rfc822msgid_and_content_sample",
    verification_receipt: dict[str, str] | None = None,
) -> int:
    gate = checkpoint.get("verification_gate")
    if not isinstance(gate, dict) or gate.get("status") not in {
        "required",
        "collecting",
        "blocked",
    }:
        raise ImportSafetyError("There is no batch awaiting verification.")
    if not gate.get("item_keys"):
        raise ImportSafetyError("The interrupted batch has no successful rows to verify.")
    now = utc_now()
    source_ids = []
    gmail_message_ids = {}
    for item_key in gate["item_keys"]:
        state = checkpoint["states"][item_key]
        if state.get("status") != "imported_pending_verification":
            raise ImportSafetyError("A last-batch row is not pending verification.")
        state["status"] = "verified"
        state["verified_manually_at"] = now
        state["verification_method"] = verification_method
        state["manual_verification_required"] = False
        source_ids.append(int(state["source_id"]))
        gmail_message_ids[item_key] = str(state["gmail_message_id"])
    batch_receipt = {
        "batch_sequence": gate["batch_sequence"],
        "verified_at": now,
        "item_count": len(gate["item_keys"]),
        "item_keys": list(gate["item_keys"]),
        "gmail_message_ids": gmail_message_ids,
        "source_ids": source_ids,
        "verification_method": verification_method,
    }
    if verification_receipt is not None:
        batch_receipt["verification_receipt"] = verification_receipt
    checkpoint["verified_batches"].append(batch_receipt)
    remaining_blockers = blocking_states(checkpoint)
    if remaining_blockers:
        gate["status"] = "blocked"
        gate["verified_completed_item_keys"] = list(gate["item_keys"])
        gate["item_keys"] = []
        gate["source_ids"] = []
        gate["successful_subset_verified_at"] = now
    else:
        checkpoint["verification_gate"] = None
    checkpoint["updated_at"] = now
    write_json_atomic(checkpoint_path, checkpoint)
    print("batch_verified:", gate["batch_sequence"])
    print("messages_marked_verified:", len(source_ids))
    print("verification_method:", verification_method)
    if remaining_blockers:
        print("remaining_blocking_states:", remaining_blockers)
    print("gmail_writes_this_run: 0")
    return 0


def reconcile_source_954_preflight_failure(
    checkpoint_path: Path,
    checkpoint: dict[str, Any],
    rows: list[dict],
) -> int:
    """Reset the one proven-unsent Python 3.14 multipart construction failure."""
    row = next((row for row in rows if int(row["source_id"]) == 954), None)
    if (
        row is None
        or row.get("item_key") != SOURCE_954_ITEM_KEY
        or row.get("message_id") != SOURCE_954_MESSAGE_ID
    ):
        raise ImportSafetyError("Source 954 no longer matches the audited manifest row.")
    state = checkpoint["states"][SOURCE_954_ITEM_KEY]
    if (
        state.get("status") != "uncertain"
        or state.get("error_type") != "UnicodeEncodeError"
        or state.get("gmail_message_id")
        or state.get("imported_at")
    ):
        raise ImportSafetyError(
            "Source 954 is not the exact receiptless UnicodeEncodeError state."
        )
    gate = checkpoint.get("verification_gate")
    if (
        not isinstance(gate, dict)
        or gate.get("status") != "blocked"
        or SOURCE_954_ITEM_KEY not in gate.get("planned_item_keys", [])
        or SOURCE_954_ITEM_KEY in gate.get("item_keys", [])
    ):
        raise ImportSafetyError("The interrupted batch no longer isolates source 954.")

    # Reproduce the legacy non-resumable request construction with anonymous
    # credentials.  Calling import_ constructs the multipart body locally;
    # execute() is deliberately never called.  The expected UnicodeEncodeError
    # therefore proves that the recorded attempt could not have reached Gmail.
    reproduced = False
    with upload_path_for(row, checkpoint_path) as upload_path:
        service = build(
            "gmail", "v1", credentials=AnonymousCredentials(), cache_discovery=False
        )
        media = MediaFileUpload(
            str(upload_path), mimetype="message/rfc822", resumable=False
        )
        try:
            service.users().messages().import_(
                userId="me",
                body={"labelIds": ["INBOX"]},
                media_body=media,
                internalDateSource="dateHeader",
                neverMarkSpam=True,
                processForCalendar=False,
                deleted=False,
                fields="id",
            )
        except UnicodeEncodeError:
            reproduced = True
    if not reproduced:
        raise ImportSafetyError(
            "Could not reproduce the pre-request source 954 encoding failure."
        )

    original_attempted_at = state.get("attempted_at")
    for field in (
        "attempted_at",
        "error_type",
        "error_phase",
        "http_status",
        "error",
        "upload_mode",
    ):
        state.pop(field, None)
    state["status"] = "pending"
    history = state.setdefault("reconciliation_history", [])
    history.append(
        {
            "at": utc_now(),
            "outcome": "definitely_unsent",
            "original_attempted_at": original_attempted_at,
            "original_error_type": "UnicodeEncodeError",
            "method": (
                "reproduced_googleapiclient_nonresumable_multipart_failure_"
                "before_execute"
            ),
        }
    )
    reconciled_ids = gate.setdefault("reconciled_unsent_source_ids", [])
    if 954 not in reconciled_ids:
        reconciled_ids.append(954)
    checkpoint["updated_at"] = utc_now()
    write_json_atomic(checkpoint_path, checkpoint)
    print("source_954_reconciliation: definitely_unsent")
    print("source_954_status: pending")
    print("gmail_writes_this_run: 0")
    return 0


def parse_utc_timestamp(value: str, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ImportSafetyError(f"Invalid {field} timestamp in reconciliation evidence.") from exc
    if parsed.tzinfo is None:
        raise ImportSafetyError(f"Naive {field} timestamp in reconciliation evidence.")
    return parsed.astimezone(timezone.utc)


def compact_header(value: Any) -> str:
    return " ".join(str(value or "").split())


def rfc2822_date_semantics(value: Any) -> tuple[int, int] | None:
    """Normalize an RFC 2822 date by instant and its stated UTC offset."""
    try:
        parsed = parsedate_to_datetime(str(value or ""))
    except (TypeError, ValueError, OverflowError):
        return None
    if parsed is None or parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return (
        int(parsed.timestamp() * 1000),
        int(parsed.utcoffset().total_seconds()),
    )


def reconcile_source_1632_readonly_evidence(
    checkpoint_path: Path,
    checkpoint: dict[str, Any],
    rows: list[dict],
    evidence_path: Path,
) -> int:
    """Resolve the interrupted source 1632 request without risking a retry."""
    row = next(
        (row for row in rows if int(row["source_id"]) == SOURCE_1632_ID), None
    )
    if (
        row is None
        or row.get("item_key") != SOURCE_1632_ITEM_KEY
        or row.get("source_sha256") != SOURCE_1632_ITEM_KEY
        or row.get("message_id") != SOURCE_1632_MESSAGE_ID
    ):
        raise ImportSafetyError("Source 1632 no longer matches the audited manifest row.")

    state = checkpoint["states"][SOURCE_1632_ITEM_KEY]
    if (
        state.get("status") != "uncertain"
        or state.get("error_type") != "KeyboardInterrupt"
        or state.get("error_phase") != "request_execution"
        or not state.get("attempted_at")
        or state.get("gmail_message_id")
        or state.get("imported_at")
    ):
        raise ImportSafetyError(
            "Source 1632 is not the exact receiptless interrupted-request state."
        )

    gate = checkpoint.get("verification_gate")
    if (
        not isinstance(gate, dict)
        or gate.get("status") != "blocked"
        or gate.get("batch_sequence") != 12
        or checkpoint.get("batch_sequence") != 12
        or SOURCE_1632_ITEM_KEY not in gate.get("planned_item_keys", [])
        or SOURCE_1632_ITEM_KEY in gate.get("item_keys", [])
        or SOURCE_1632_ID not in gate.get("planned_source_ids", [])
        or SOURCE_1632_ID in gate.get("source_ids", [])
        or len(gate.get("item_keys", [])) != 12
        or len(gate.get("source_ids", [])) != 12
    ):
        raise ImportSafetyError("Interrupted batch 12 no longer isolates source 1632.")
    completed_count = len(gate["item_keys"])
    if (
        gate["planned_item_keys"][completed_count] != SOURCE_1632_ITEM_KEY
        or gate["planned_source_ids"][completed_count] != SOURCE_1632_ID
    ):
        raise ImportSafetyError("Source 1632 is no longer next in the batch-12 plan.")
    if any(
        receipt.get("batch_sequence") == 12
        for receipt in checkpoint.get("verified_batches", [])
    ):
        raise ImportSafetyError("Batch sequence 12 already has a verification receipt.")

    if evidence_path.resolve().parent != checkpoint_path.resolve().parent:
        raise ImportSafetyError("Source 1632 evidence must be in the checkpoint directory.")
    evidence = load_json(evidence_path)
    evidence_sha256 = sha256_file(evidence_path)
    expected_scopes = {
        "openid",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/gmail.readonly",
    }
    expected_queries = {
        f"in:anywhere rfc822msgid:{SOURCE_1632_MESSAGE_ID}",
        'in:anywhere rfc822msgid:example-34730551@example.org',
    }
    if (
        evidence.get("schema_version") != 1
        or evidence.get("source_id") != SOURCE_1632_ID
        or evidence.get("source_sha256") != SOURCE_1632_ITEM_KEY
        or evidence.get("expected_destination") != DESTINATION
        or evidence.get("authorized_email") != DESTINATION
        or evidence.get("exact_account_match") is not True
        or evidence.get("oauth_client_id") != OAUTH_CLIENT_ID
        or set(evidence.get("requested_oauth_scopes", [])) != expected_scopes
        or not expected_scopes.issubset(
            set(evidence.get("granted_oauth_scopes", []))
        )
        or set(evidence.get("queries", [])) != expected_queries
        or evidence.get("include_spam_trash") is not True
        or evidence.get("all_queries_exhausted") is not True
        or evidence.get("gmail_mutations") != 0
        or evidence.get("token_persisted") is not False
        or evidence.get("source_internal_date_ms") != SOURCE_1632_INTERNAL_DATE_MS
        or evidence.get("source_headers") != SOURCE_1632_HEADERS
    ):
        raise ImportSafetyError("Source 1632 read-only evidence header is invalid.")

    passes = evidence.get("search_passes")
    candidates = evidence.get("candidates")
    if not isinstance(passes, list) or not passes or not isinstance(candidates, list):
        raise ImportSafetyError("Source 1632 read-only evidence rows are invalid.")
    for search_pass in passes:
        receipts = search_pass.get("query_receipts")
        if not isinstance(receipts, list) or len(receipts) != 2:
            raise ImportSafetyError("Source 1632 search pass is incomplete.")
        if {receipt.get("query") for receipt in receipts} != expected_queries:
            raise ImportSafetyError("Source 1632 search queries changed.")
        if any(receipt.get("all_pages_exhausted") is not True for receipt in receipts):
            raise ImportSafetyError("Source 1632 search pagination is incomplete.")

    message_id_matches = []
    fully_confirmed = []
    expected_date_semantics = rfc2822_date_semantics(SOURCE_1632_HEADERS["Date"])
    if expected_date_semantics is None:
        raise ImportSafetyError("Source 1632 expected Date header is invalid.")
    for candidate in candidates:
        headers = candidate.get("headers")
        if not isinstance(headers, dict):
            raise ImportSafetyError("Source 1632 candidate headers are invalid.")
        message_id_match = compact_header(headers.get("Message-ID")) == compact_header(
            SOURCE_1632_MESSAGE_ID
        )
        if message_id_match:
            message_id_matches.append(candidate)
        text_headers_match = all(
            compact_header(headers.get(name))
            == compact_header(SOURCE_1632_HEADERS[name])
            for name in ("Subject", "From", "To")
        )
        date_header_matches = (
            rfc2822_date_semantics(headers.get("Date")) == expected_date_semantics
        )
        core_headers_match = text_headers_match and date_header_matches
        is_fully_confirmed = (
            message_id_match
            and core_headers_match
            and "INBOX" in candidate.get("label_ids", [])
            and str(candidate.get("internal_date_ms", ""))
            == SOURCE_1632_INTERNAL_DATE_MS
            and bool(candidate.get("gmail_message_id"))
        )
        if is_fully_confirmed:
            fully_confirmed.append(candidate)
    if (
        evidence.get("message_id_match_count") != len(message_id_matches)
        or evidence.get("exact_match_count") != len(fully_confirmed)
    ):
        raise ImportSafetyError("Source 1632 evidence result counts do not reconcile.")
    if len(message_id_matches) > 1 or (
        message_id_matches and len(fully_confirmed) != 1
    ):
        raise ImportSafetyError(
            "Source 1632 has ambiguous Gmail evidence; the checkpoint was not changed."
        )

    checkpoint_bytes = checkpoint_path.read_bytes()
    checkpoint_sha256 = hashlib.sha256(checkpoint_bytes).hexdigest()
    backup_path = checkpoint_path.with_name(
        f"checkpoint.pre-source1632-reconciliation-{checkpoint_sha256[:16]}.json"
    )
    if backup_path.exists():
        if backup_path.read_bytes() != checkpoint_bytes:
            raise ImportSafetyError("Source 1632 checkpoint backup path already drifted.")
    else:
        backup_path.write_bytes(checkpoint_bytes)

    now = utc_now()
    original_receipt = {
        "attempted_at": state.get("attempted_at"),
        "upload_mode": state.get("upload_mode"),
        "error_type": state.get("error_type"),
        "error_phase": state.get("error_phase"),
        "interrupted_at": state.get("interrupted_at"),
    }
    history = state.setdefault("reconciliation_history", [])
    if not isinstance(history, list):
        raise ImportSafetyError("Source 1632 reconciliation history is invalid.")

    if len(fully_confirmed) == 1:
        candidate = fully_confirmed[0]
        gmail_id = str(candidate["gmail_message_id"])
        existing_ids = {
            str(other.get("gmail_message_id"))
            for key, other in checkpoint["states"].items()
            if key != SOURCE_1632_ITEM_KEY and other.get("gmail_message_id")
        }
        if gmail_id in existing_ids:
            raise ImportSafetyError(
                "Source 1632 read-back Gmail ID already exists in the checkpoint."
            )
        history.append(
            {
                "at": now,
                "outcome": "already_imported_confirmed",
                "original_receipt": original_receipt,
                "method": "gmail_api_readonly_exact_rfc822msgid_headers_and_date",
                "evidence": str(evidence_path),
                "evidence_sha256": evidence_sha256,
            }
        )
        for field in (
            "error_type",
            "error_phase",
            "interrupted_at",
            "http_status",
            "error",
        ):
            state.pop(field, None)
        state.update(
            status="imported_pending_verification",
            gmail_message_id=gmail_id,
            imported_at=now,
            imported_at_basis="read_only_reconciliation_after_interrupted_response",
            manual_verification_required=True,
            reconciliation_evidence=str(evidence_path),
            reconciliation_evidence_sha256=evidence_sha256,
        )
        gate["item_keys"].append(SOURCE_1632_ITEM_KEY)
        gate["source_ids"].append(SOURCE_1632_ID)
        gate["status"] = "required"
        verification_method = (
            "12_gmail_api_response_ids_plus_1_exact_readonly_"
            "rfc822msgid_header_readback"
        )
        outcome = "already_imported_confirmed"
    else:
        if len(passes) < 2:
            raise ImportSafetyError(
                "A zero-result source 1632 reconciliation requires two search passes."
            )
        pass_times = [
            parse_utc_timestamp(str(search_pass.get("checked_at", "")), "search-pass")
            for search_pass in passes
        ]
        if (pass_times[-1] - pass_times[0]).total_seconds() < SOURCE_1632_ZERO_RECHECK_SECONDS:
            raise ImportSafetyError("Source 1632 zero-result searches were too close.")
        attempted_at = parse_utc_timestamp(str(state["attempted_at"]), "attempted-at")
        if (
            pass_times[-1] - attempted_at
        ).total_seconds() < SOURCE_1632_MIN_ABSENCE_AGE_SECONDS:
            raise ImportSafetyError("Source 1632 absence check was performed too early.")
        history.append(
            {
                "at": now,
                "outcome": "definitely_absent_after_readonly_searches",
                "original_receipt": original_receipt,
                "method": "two_gmail_api_readonly_exact_rfc822msgid_searches",
                "evidence": str(evidence_path),
                "evidence_sha256": evidence_sha256,
            }
        )
        for field in (
            "attempted_at",
            "gmail_message_id",
            "imported_at",
            "verified_manually_at",
            "upload_mode",
            "error_type",
            "error_phase",
            "interrupted_at",
            "http_status",
            "error",
            "manual_verification_required",
            "verification_method",
        ):
            state.pop(field, None)
        state["status"] = "pending"
        verification_method = (
            "gmail_api_response_ids_after_two_readonly_zero_match_searches"
        )
        outcome = "definitely_absent_retry_safe"

    checkpoint["updated_at"] = now
    result = record_last_batch_verified(
        checkpoint_path,
        checkpoint,
        verification_method=verification_method,
        verification_receipt={
            "basis": (
                "12 unique Gmail API response IDs plus bounded source 1632 "
                "read-only reconciliation"
            ),
            "destination_guard": "exact OAuth email match before mailbox read",
            "source_1632_outcome": outcome,
            "source_1632_evidence": str(evidence_path),
            "source_1632_evidence_sha256": evidence_sha256,
            "pretransition_checkpoint_sha256": checkpoint_sha256,
            "post_import_readback": "performed only for source 1632",
        },
    )
    print("source_1632_reconciliation:", outcome)
    print("checkpoint_backup:", backup_path)
    print("checkpoint_backup_sha256:", checkpoint_sha256)
    return result


def apply_security_attachment_exclusions(
    checkpoint_path: Path,
    checkpoint: dict[str, Any],
    rows: list[dict],
) -> int:
    """Resolve the blocked batch by preserving unsafe messages locally only."""
    if checkpoint.get("security_attachment_policy") is not None:
        print("security_attachment_exclusions_already_applied: true")
        print("gmail_writes_this_run: 0")
        return 0
    evidence = load_security_exclusions(rows)
    evidence_by_id = {
        int(item["source_id"]): item for item in evidence.get("items", [])
    }
    gate = checkpoint.get("verification_gate")
    if (
        checkpoint.get("batch_sequence") != 4
        or not isinstance(gate, dict)
        or gate.get("status") != "blocked"
        or gate.get("batch_sequence") != 4
        or gate.get("item_keys") != []
        or gate.get("source_ids") != []
        or len(gate.get("planned_item_keys", [])) != 250
        or len(set(gate.get("planned_item_keys", []))) != 250
        or len(gate.get("planned_source_ids", [])) != 250
        or len(set(gate.get("planned_source_ids", []))) != 250
        or len(gate.get("verified_completed_item_keys", [])) != 179
        or len(set(gate.get("verified_completed_item_keys", []))) != 179
    ):
        raise ImportSafetyError(
            "The checkpoint is not the exact blocked batch-4 state audited for recovery."
        )
    planned_item_keys = gate["planned_item_keys"]
    planned_source_ids = gate["planned_source_ids"]
    if any(item_key not in checkpoint["states"] for item_key in planned_item_keys) or [
        int(checkpoint["states"][item_key]["source_id"])
        for item_key in planned_item_keys
    ] != [int(source_id) for source_id in planned_source_ids]:
        raise ImportSafetyError("The blocked batch-4 plan no longer reconciles.")
    batch_four_receipts = [
        receipt
        for receipt in checkpoint.get("verified_batches", [])
        if receipt.get("batch_sequence") == 4
    ]
    if (
        len(batch_four_receipts) != 1
        or batch_four_receipts[0].get("item_count") != 179
        or set(batch_four_receipts[0].get("item_keys", []))
        != set(gate["verified_completed_item_keys"])
        or batch_four_receipts[0].get("verified_at")
        != gate.get("successful_subset_verified_at")
    ):
        raise ImportSafetyError(
            "The 179 successful batch-4 receipts no longer match the blocked gate."
        )

    source_65_item_key = evidence_by_id[65]["item_key"]
    source_65_state = checkpoint["states"][source_65_item_key]
    verified_completed_keys = set(gate["verified_completed_item_keys"])
    planned_key_set = set(planned_item_keys)
    unattempted_item_keys = [
        item_key
        for item_key in planned_item_keys
        if item_key not in verified_completed_keys and item_key != source_65_item_key
    ]
    security_ids_in_plan = {
        int(checkpoint["states"][item_key]["source_id"])
        for item_key in planned_item_keys
        if int(checkpoint["states"][item_key]["source_id"])
        in SECURITY_EXCLUSION_IDS
    }
    if (
        source_65_item_key not in planned_key_set
        or source_65_item_key in verified_completed_keys
        or not verified_completed_keys.issubset(planned_key_set)
        or len(unattempted_item_keys) != 70
        or security_ids_in_plan != {65, 89, 128, 129, 133, 137}
        or blocking_states(checkpoint) != [(65, "failed")]
        or source_65_state.get("status") != "failed"
        or source_65_state.get("http_status") != 400
        or source_65_state.get("error") != SOURCE_65_ERROR
        or source_65_state.get("upload_mode") != "resumable_rfc822"
        or source_65_state.get("attempted_at") != SOURCE_65_ATTEMPTED_AT
        or source_65_state.get("gmail_message_id")
        or source_65_state.get("imported_at")
    ):
        raise ImportSafetyError("Source 65 no longer has its exact Gmail rejection receipt.")
    if any(
        checkpoint["states"][item_key].get("status") != "pending"
        for item_key in unattempted_item_keys
    ):
        raise ImportSafetyError(
            "The blocked batch-4 remainder is no longer exactly 70 pending rows."
        )
    for source_id in SECURITY_EXCLUSION_IDS - {65}:
        state = checkpoint["states"][evidence_by_id[source_id]["item_key"]]
        if state.get("status") != "pending" or any(
            state.get(field)
            for field in (
                "gmail_message_id",
                "attempted_at",
                "imported_at",
                "verified_manually_at",
                "http_status",
                "error",
                "error_type",
                "error_phase",
                "upload_mode",
            )
        ):
            raise ImportSafetyError(
                f"Security exclusion source {source_id} is no longer untouched and pending."
            )

    now = utc_now()
    archived_gate = deepcopy(gate)
    archived_source_65_state = deepcopy(source_65_state)
    for source_id in sorted(SECURITY_EXCLUSION_IDS):
        evidence_item = evidence_by_id[source_id]
        item_key = evidence_item["item_key"]
        state = checkpoint["states"][item_key]
        state.update(
            status="skipped_security_attachment",
            security_excluded_at=now,
            security_exclusion_manifest=str(SECURITY_EXCLUSIONS),
            security_exclusion_manifest_sha256=SECURITY_EXCLUSIONS_SHA256,
            security_classification=evidence_item["classification"],
            archive_magic=evidence_item["archive_magic"],
            attachment_filename=evidence_item["attachment_filename"],
            attachment_content_type=evidence_item["attachment_content_type"],
            attachment_size_bytes=evidence_item["attachment_size_bytes"],
            attachment_sha256=evidence_item["attachment_sha256"],
            blocked_members=evidence_item["blocked_members"],
            source_preservation=evidence_item["source_preservation"],
            source_preserved_path=str(SOURCE_ROOT / state["relative_path"]),
            source_preserved_sha256=state["source_sha256"],
            gmail_write_attempted=source_id == 65,
            gmail_outcome=(
                "definite_rejection_no_message_id"
                if source_id == 65
                else "not_attempted"
            ),
            status_before_security_exclusion=(
                "failed" if source_id == 65 else "pending"
            ),
        )

    checkpoint["security_attachment_policy"] = {
        "status": "applied",
        "applied_at": now,
        "security_exclusion_count": SECURITY_EXCLUSION_COUNT,
        "security_exclusion_source_ids": sorted(SECURITY_EXCLUSION_IDS),
        "evidence_manifest": str(SECURITY_EXCLUSIONS),
        "evidence_manifest_sha256": SECURITY_EXCLUSIONS_SHA256,
        "original_target_gmail_messages": EXPECTED_TARGET_TOTAL,
        "effective_target_gmail_messages": EFFECTIVE_TARGET_TOTAL,
        "original_new_api_imports": EXPECTED_NEW_IMPORTS,
        "effective_new_api_imports": EFFECTIVE_NEW_IMPORTS,
        "source_preservation": "original_eml_unchanged_local_only",
        "gmail_write_policy": "users.messages.import_only_no_scanning_bypass",
        "blocked_batch_recovery": {
            "batch_sequence": 4,
            "failed_source_id": 65,
            "failed_http_status": 400,
            "gmail_message_id_returned": False,
            "gate_cleared_at": now,
            "unattempted_item_keys_at_recovery": unattempted_item_keys,
            "security_exclusion_source_ids_in_blocked_plan": sorted(
                security_ids_in_plan
            ),
            "verification_gate_before_recovery": archived_gate,
            "failed_source_state_before_recovery": archived_source_65_state,
        },
    }
    checkpoint["verification_gate"] = None
    checkpoint["updated_at"] = now
    write_json_atomic(checkpoint_path, checkpoint)
    counts = status_counts(checkpoint)
    print("security_attachment_exclusions_applied:", SECURITY_EXCLUSION_COUNT)
    print("security_exclusion_source_ids:", sorted(SECURITY_EXCLUSION_IDS))
    print("original_emls_preserved_unchanged:", SECURITY_EXCLUSION_COUNT)
    print("effective_target_gmail_messages:", EFFECTIVE_TARGET_TOTAL)
    print("safe_pending_imports:", counts.get("pending", 0))
    print("recovered_blocked_batch: 4")
    print("gmail_writes_this_run: 0")
    return 0


def apply_html_phishing_security_exclusions(
    checkpoint_path: Path,
    checkpoint: dict[str, Any],
    rows: list[dict],
) -> int:
    """Keep credential-phishing HTML messages local-only and recover batch 5."""
    if checkpoint.get("html_phishing_security_policy") is not None:
        print("html_phishing_security_exclusions_already_applied: true")
        print("gmail_writes_this_run: 0")
        return 0
    if checkpoint.get("security_attachment_policy") is None:
        raise ImportSafetyError(
            "The earlier 20 attachment security exclusions are not applied."
        )
    evidence = load_html_phishing_exclusions(rows)
    evidence_by_id = {
        int(item["source_id"]): item for item in evidence.get("items", [])
    }
    gate = checkpoint.get("verification_gate")
    if (
        checkpoint.get("batch_sequence") != 5
        or not isinstance(gate, dict)
        or gate.get("status") != "blocked"
        or gate.get("batch_sequence") != 5
        or gate.get("item_keys") != []
        or gate.get("source_ids") != []
        or len(gate.get("planned_item_keys", [])) != 250
        or len(set(gate.get("planned_item_keys", []))) != 250
        or len(gate.get("planned_source_ids", [])) != 250
        or len(set(gate.get("planned_source_ids", []))) != 250
        or len(gate.get("verified_completed_item_keys", [])) != 6
        or len(set(gate.get("verified_completed_item_keys", []))) != 6
    ):
        raise ImportSafetyError(
            "The checkpoint is not the exact blocked batch-5 state audited for recovery."
        )
    planned_item_keys = gate["planned_item_keys"]
    planned_source_ids = gate["planned_source_ids"]
    if any(item_key not in checkpoint["states"] for item_key in planned_item_keys) or [
        int(checkpoint["states"][item_key]["source_id"])
        for item_key in planned_item_keys
    ] != [int(source_id) for source_id in planned_source_ids]:
        raise ImportSafetyError("The blocked batch-5 plan no longer reconciles.")
    batch_five_receipts = [
        receipt
        for receipt in checkpoint.get("verified_batches", [])
        if receipt.get("batch_sequence") == 5
    ]
    if (
        len(batch_five_receipts) != 1
        or batch_five_receipts[0].get("item_count") != 6
        or set(batch_five_receipts[0].get("item_keys", []))
        != set(gate["verified_completed_item_keys"])
        or batch_five_receipts[0].get("verified_at")
        != gate.get("successful_subset_verified_at")
    ):
        raise ImportSafetyError(
            "The six successful batch-5 receipts no longer match the blocked gate."
        )

    source_74_item_key = evidence_by_id[74]["item_key"]
    source_74_state = checkpoint["states"][source_74_item_key]
    verified_completed_keys = set(gate["verified_completed_item_keys"])
    planned_key_set = set(planned_item_keys)
    unattempted_item_keys = [
        item_key
        for item_key in planned_item_keys
        if item_key not in verified_completed_keys and item_key != source_74_item_key
    ]
    security_ids_in_plan = {
        int(checkpoint["states"][item_key]["source_id"])
        for item_key in planned_item_keys
        if int(checkpoint["states"][item_key]["source_id"])
        in HTML_PHISHING_EXCLUSION_IDS
    }
    if (
        source_74_item_key not in planned_key_set
        or source_74_item_key in verified_completed_keys
        or not verified_completed_keys.issubset(planned_key_set)
        or len(unattempted_item_keys) != 243
        or security_ids_in_plan != {74, 76, 146, 147, 188, 333}
        or blocking_states(checkpoint) != [(74, "failed")]
        or source_74_state.get("status") != "failed"
        or source_74_state.get("http_status") != 400
        or source_74_state.get("error") != SOURCE_74_ERROR
        or source_74_state.get("upload_mode") != "resumable_rfc822"
        or source_74_state.get("attempted_at") != SOURCE_74_ATTEMPTED_AT
        or source_74_state.get("gmail_message_id")
        or source_74_state.get("imported_at")
    ):
        raise ImportSafetyError("Source 74 no longer has its exact Gmail rejection receipt.")
    if any(
        checkpoint["states"][item_key].get("status") != "pending"
        for item_key in unattempted_item_keys
    ):
        raise ImportSafetyError(
            "The blocked batch-5 remainder is no longer exactly 243 pending rows."
        )
    for source_id in HTML_PHISHING_EXCLUSION_IDS - {74}:
        state = checkpoint["states"][evidence_by_id[source_id]["item_key"]]
        if state.get("status") != "pending" or any(
            state.get(field)
            for field in (
                "gmail_message_id",
                "attempted_at",
                "imported_at",
                "verified_manually_at",
                "http_status",
                "error",
                "error_type",
                "error_phase",
                "upload_mode",
            )
        ):
            raise ImportSafetyError(
                f"HTML-phishing source {source_id} is no longer untouched and pending."
            )

    now = utc_now()
    archived_gate = deepcopy(gate)
    archived_source_74_state = deepcopy(source_74_state)
    for source_id in sorted(HTML_PHISHING_EXCLUSION_IDS):
        evidence_item = evidence_by_id[source_id]
        state = checkpoint["states"][evidence_item["item_key"]]
        state.update(
            status="skipped_security_html_phishing",
            security_excluded_at=now,
            security_exclusion_manifest=str(HTML_PHISHING_EXCLUSIONS),
            security_exclusion_manifest_sha256=HTML_PHISHING_EXCLUSIONS_SHA256,
            security_classification=evidence_item["classification"],
            security_indicators=evidence_item["indicators"],
            attachment_filename=evidence_item["attachment_filename"],
            attachment_content_type=evidence_item["attachment_content_type"],
            attachment_size_bytes=evidence_item["attachment_size_bytes"],
            attachment_sha256=evidence_item["attachment_sha256"],
            source_preservation=evidence_item["source_preservation"],
            source_preserved_path=str(SOURCE_ROOT / state["relative_path"]),
            source_preserved_sha256=state["source_sha256"],
            gmail_write_attempted=source_id == 74,
            gmail_outcome=evidence_item["gmail_outcome_at_detection"],
            status_before_security_exclusion=(
                "failed" if source_id == 74 else "pending"
            ),
        )

    checkpoint["html_phishing_security_policy"] = {
        "status": "applied",
        "applied_at": now,
        "security_exclusion_count": HTML_PHISHING_EXCLUSION_COUNT,
        "security_exclusion_source_ids": sorted(HTML_PHISHING_EXCLUSION_IDS),
        "evidence_manifest": str(HTML_PHISHING_EXCLUSIONS),
        "evidence_manifest_sha256": HTML_PHISHING_EXCLUSIONS_SHA256,
        "original_target_gmail_messages": EXPECTED_TARGET_TOTAL,
        "prior_effective_target_gmail_messages": EFFECTIVE_TARGET_TOTAL,
        "effective_target_gmail_messages": SAFE_TARGET_TOTAL_AFTER_HTML_EXCLUSIONS,
        "original_new_api_imports": EXPECTED_NEW_IMPORTS,
        "prior_effective_new_api_imports": EFFECTIVE_NEW_IMPORTS,
        "effective_new_api_imports": SAFE_NEW_IMPORTS_AFTER_HTML_EXCLUSIONS,
        "total_security_exclusion_count": TOTAL_SECURITY_EXCLUSION_COUNT,
        "source_preservation": "original_eml_unchanged_local_only",
        "gmail_write_policy": "users.messages.import_only_no_scanning_bypass",
        "blocked_batch_recovery": {
            "batch_sequence": 5,
            "failed_source_id": 74,
            "failed_http_status": 400,
            "gmail_message_id_returned": False,
            "gate_cleared_at": now,
            "unattempted_item_keys_at_recovery": unattempted_item_keys,
            "security_exclusion_source_ids_in_blocked_plan": sorted(
                security_ids_in_plan
            ),
            "verification_gate_before_recovery": archived_gate,
            "failed_source_state_before_recovery": archived_source_74_state,
        },
    }
    checkpoint["verification_gate"] = None
    checkpoint["updated_at"] = now
    write_json_atomic(checkpoint_path, checkpoint)
    counts = status_counts(checkpoint)
    print(
        "html_phishing_security_exclusions_applied:",
        HTML_PHISHING_EXCLUSION_COUNT,
    )
    print(
        "html_phishing_exclusion_source_ids:",
        sorted(HTML_PHISHING_EXCLUSION_IDS),
    )
    print("total_security_messages_kept_local_only:", TOTAL_SECURITY_EXCLUSION_COUNT)
    print("effective_target_gmail_messages:", SAFE_TARGET_TOTAL_AFTER_HTML_EXCLUSIONS)
    print("safe_pending_imports:", counts.get("pending", 0))
    print("recovered_blocked_batch: 5")
    print("gmail_writes_this_run: 0")
    return 0


def apply_html_redirect_security_exclusions(
    checkpoint_path: Path,
    checkpoint: dict[str, Any],
    rows: list[dict],
) -> int:
    """Keep four external redirect phishing lures local-only."""
    if checkpoint.get("html_redirect_security_policy") is not None:
        print("html_redirect_security_exclusions_already_applied: true")
        print("gmail_writes_this_run: 0")
        return 0
    if checkpoint.get("html_phishing_security_policy") is None:
        raise ImportSafetyError(
            "The credential-phishing HTML exclusions are not applied."
        )
    evidence = load_html_redirect_exclusions(rows)
    evidence_by_id = {
        int(item["source_id"]): item for item in evidence.get("items", [])
    }
    expected_before = Counter(
        {
            "pending": 1663,
            "verified": 300,
            "verified_pilot": 5,
            "skipped_semantic_duplicate": 3,
            "skipped_security_attachment": 20,
            "skipped_security_html_phishing": 14,
        }
    )
    if (
        checkpoint.get("batch_sequence") != 5
        or checkpoint.get("verification_gate") is not None
        or blocking_states(checkpoint)
        or status_counts(checkpoint) != expected_before
    ):
        raise ImportSafetyError(
            "The checkpoint is not the exact post-batch-5 state audited for redirect exclusions."
        )
    for source_id in HTML_REDIRECT_EXCLUSION_IDS:
        state = checkpoint["states"][evidence_by_id[source_id]["item_key"]]
        if state.get("status") != "pending" or any(
            state.get(field)
            for field in (
                "gmail_message_id",
                "attempted_at",
                "imported_at",
                "verified_manually_at",
                "http_status",
                "error",
                "error_type",
                "error_phase",
                "upload_mode",
            )
        ):
            raise ImportSafetyError(
                f"HTML-redirect source {source_id} is no longer untouched and pending."
            )
    now = utc_now()
    for source_id in sorted(HTML_REDIRECT_EXCLUSION_IDS):
        evidence_item = evidence_by_id[source_id]
        state = checkpoint["states"][evidence_item["item_key"]]
        state.update(
            status="skipped_security_html_redirect",
            security_excluded_at=now,
            security_exclusion_manifest=str(HTML_REDIRECT_EXCLUSIONS),
            security_exclusion_manifest_sha256=HTML_REDIRECT_EXCLUSIONS_SHA256,
            security_classification=evidence_item["classification"],
            security_indicators=evidence_item["indicators"],
            attachment_filename=evidence_item["attachment_filename"],
            attachment_content_type=evidence_item["attachment_content_type"],
            attachment_size_bytes=evidence_item["attachment_size_bytes"],
            attachment_sha256=evidence_item["attachment_sha256"],
            source_preservation=evidence_item["source_preservation"],
            source_preserved_path=str(SOURCE_ROOT / state["relative_path"]),
            source_preserved_sha256=state["source_sha256"],
            gmail_write_attempted=False,
            gmail_outcome=evidence_item["gmail_outcome_at_detection"],
            status_before_security_exclusion="pending",
        )
    checkpoint["html_redirect_security_policy"] = {
        "status": "applied",
        "applied_at": now,
        "security_exclusion_count": HTML_REDIRECT_EXCLUSION_COUNT,
        "security_exclusion_source_ids": sorted(HTML_REDIRECT_EXCLUSION_IDS),
        "evidence_manifest": str(HTML_REDIRECT_EXCLUSIONS),
        "evidence_manifest_sha256": HTML_REDIRECT_EXCLUSIONS_SHA256,
        "original_target_gmail_messages": EXPECTED_TARGET_TOTAL,
        "prior_effective_target_gmail_messages": (
            SAFE_TARGET_TOTAL_AFTER_HTML_EXCLUSIONS
        ),
        "effective_target_gmail_messages": FINAL_SAFE_TARGET_TOTAL,
        "original_new_api_imports": EXPECTED_NEW_IMPORTS,
        "prior_effective_new_api_imports": SAFE_NEW_IMPORTS_AFTER_HTML_EXCLUSIONS,
        "effective_new_api_imports": FINAL_SAFE_NEW_IMPORTS,
        "total_security_exclusion_count": FINAL_SECURITY_EXCLUSION_COUNT,
        "source_preservation": "original_eml_unchanged_local_only",
        "gmail_write_policy": "users.messages.import_only_no_scanning_bypass",
        "checkpoint_transition": {
            "applied_at": now,
            "batch_sequence_at_application": 5,
            "verification_gate_was_clear": True,
            "pending_before": 1663,
            "pending_after": 1659,
            "excluded_source_ids": sorted(HTML_REDIRECT_EXCLUSION_IDS),
        },
    }
    checkpoint["updated_at"] = now
    write_json_atomic(checkpoint_path, checkpoint)
    counts = status_counts(checkpoint)
    print("html_redirect_security_exclusions_applied:", HTML_REDIRECT_EXCLUSION_COUNT)
    print("html_redirect_exclusion_source_ids:", sorted(HTML_REDIRECT_EXCLUSION_IDS))
    print("total_security_messages_kept_local_only:", FINAL_SECURITY_EXCLUSION_COUNT)
    print("effective_target_gmail_messages:", FINAL_SAFE_TARGET_TOTAL)
    print("safe_pending_imports:", counts.get("pending", 0))
    print("gmail_writes_this_run: 0")
    return 0


def apply_body_phishing_security_exclusions(
    checkpoint_path: Path,
    checkpoint: dict[str, Any],
    rows: list[dict],
) -> int:
    """Keep verified body-link phishing local-only and recover blocked batch 6."""
    if checkpoint.get("body_phishing_security_policy") is not None:
        print("body_phishing_security_exclusions_already_applied: true")
        print("gmail_writes_this_run: 0")
        return 0
    if checkpoint.get("html_redirect_security_policy") is None:
        raise ImportSafetyError("The earlier HTML-redirect exclusions are not applied.")
    evidence = load_body_phishing_exclusions(rows)
    evidence_by_id = {
        int(item["source_id"]): item for item in evidence.get("items", [])
    }
    expected_before = Counter(
        {
            "pending": 1634,
            "failed": 1,
            "verified": 324,
            "verified_pilot": 5,
            "skipped_semantic_duplicate": 3,
            "skipped_security_attachment": 20,
            "skipped_security_html_phishing": 14,
            "skipped_security_html_redirect": 4,
        }
    )
    gate = checkpoint.get("verification_gate")
    if (
        checkpoint.get("batch_sequence") != 6
        or not isinstance(gate, dict)
        or gate.get("status") != "blocked"
        or gate.get("batch_sequence") != 6
        or gate.get("item_keys") != []
        or gate.get("source_ids") != []
        or len(gate.get("planned_item_keys", [])) != 250
        or len(set(gate.get("planned_item_keys", []))) != 250
        or len(gate.get("planned_source_ids", [])) != 250
        or len(set(gate.get("planned_source_ids", []))) != 250
        or len(gate.get("verified_completed_item_keys", [])) != 24
        or len(set(gate.get("verified_completed_item_keys", []))) != 24
        or status_counts(checkpoint) != expected_before
    ):
        raise ImportSafetyError(
            "The checkpoint is not the exact blocked batch-6 state audited for recovery."
        )
    planned_item_keys = gate["planned_item_keys"]
    planned_source_ids = gate["planned_source_ids"]
    if any(item_key not in checkpoint["states"] for item_key in planned_item_keys) or [
        int(checkpoint["states"][item_key]["source_id"])
        for item_key in planned_item_keys
    ] != [int(source_id) for source_id in planned_source_ids]:
        raise ImportSafetyError("The blocked batch-6 plan no longer reconciles.")
    batch_six_receipts = [
        receipt
        for receipt in checkpoint.get("verified_batches", [])
        if receipt.get("batch_sequence") == 6
    ]
    if (
        len(batch_six_receipts) != 1
        or batch_six_receipts[0].get("item_count") != 24
        or set(batch_six_receipts[0].get("item_keys", []))
        != set(gate["verified_completed_item_keys"])
        or batch_six_receipts[0].get("verified_at")
        != gate.get("successful_subset_verified_at")
    ):
        raise ImportSafetyError(
            "The 24 successful batch-6 receipts no longer match the blocked gate."
        )

    source_103_item_key = evidence_by_id[103]["item_key"]
    source_103_state = checkpoint["states"][source_103_item_key]
    verified_completed_keys = set(gate["verified_completed_item_keys"])
    planned_key_set = set(planned_item_keys)
    unattempted_item_keys = [
        item_key
        for item_key in planned_item_keys
        if item_key not in verified_completed_keys and item_key != source_103_item_key
    ]
    security_ids_in_plan = {
        int(checkpoint["states"][item_key]["source_id"])
        for item_key in planned_item_keys
        if int(checkpoint["states"][item_key]["source_id"])
        in BODY_PHISHING_EXCLUSION_IDS
    }
    if (
        source_103_item_key not in planned_key_set
        or source_103_item_key in verified_completed_keys
        or not verified_completed_keys.issubset(planned_key_set)
        or len(unattempted_item_keys) != 225
        or blocking_states(checkpoint) != [(103, "failed")]
        or source_103_state.get("status") != "failed"
        or source_103_state.get("http_status") != 400
        or source_103_state.get("error") != SOURCE_103_ERROR
        or source_103_state.get("upload_mode") != "resumable_rfc822"
        or source_103_state.get("attempted_at") != SOURCE_103_ATTEMPTED_AT
        or source_103_state.get("gmail_message_id")
        or source_103_state.get("imported_at")
    ):
        raise ImportSafetyError(
            "Source 103 no longer has its exact Gmail rejection receipt."
        )
    if any(
        checkpoint["states"][item_key].get("status") != "pending"
        for item_key in unattempted_item_keys
    ):
        raise ImportSafetyError(
            "The blocked batch-6 remainder is no longer exactly 225 pending rows."
        )
    for source_id in BODY_PHISHING_EXCLUSION_IDS - {103}:
        state = checkpoint["states"][evidence_by_id[source_id]["item_key"]]
        if state.get("status") != "pending" or any(
            state.get(field)
            for field in (
                "gmail_message_id",
                "attempted_at",
                "imported_at",
                "verified_manually_at",
                "http_status",
                "error",
                "error_type",
                "error_phase",
                "upload_mode",
            )
        ):
            raise ImportSafetyError(
                f"Body-phishing source {source_id} is no longer untouched and pending."
            )

    now = utc_now()
    archived_gate = deepcopy(gate)
    archived_source_103_state = deepcopy(source_103_state)
    for source_id in sorted(BODY_PHISHING_EXCLUSION_IDS):
        evidence_item = evidence_by_id[source_id]
        state = checkpoint["states"][evidence_item["item_key"]]
        state.update(
            status="skipped_security_body_phishing",
            security_excluded_at=now,
            security_exclusion_manifest=str(BODY_PHISHING_EXCLUSIONS),
            security_exclusion_manifest_sha256=BODY_PHISHING_EXCLUSIONS_SHA256,
            security_classification=evidence_item["classification"],
            security_indicators=evidence_item["indicators"],
            body_content_type=evidence_item["body_content_type"],
            body_part_index=evidence_item["body_part_index"],
            body_size_bytes=evidence_item["body_size_bytes"],
            body_sha256=evidence_item["body_sha256"],
            link_hosts=evidence_item["link_hosts"],
            source_preservation=evidence_item["source_preservation"],
            source_preserved_path=str(SOURCE_ROOT / state["relative_path"]),
            source_preserved_sha256=state["source_sha256"],
            gmail_write_attempted=source_id == 103,
            gmail_outcome=evidence_item["gmail_outcome_at_detection"],
            status_before_security_exclusion=(
                "failed" if source_id == 103 else "pending"
            ),
        )

    checkpoint["body_phishing_security_policy"] = {
        "status": "applied",
        "applied_at": now,
        "security_exclusion_count": BODY_PHISHING_EXCLUSION_COUNT,
        "security_exclusion_source_ids": sorted(BODY_PHISHING_EXCLUSION_IDS),
        "evidence_manifest": str(BODY_PHISHING_EXCLUSIONS),
        "evidence_manifest_sha256": BODY_PHISHING_EXCLUSIONS_SHA256,
        "original_target_gmail_messages": EXPECTED_TARGET_TOTAL,
        "prior_effective_target_gmail_messages": FINAL_SAFE_TARGET_TOTAL,
        "effective_target_gmail_messages": COMPLETE_SAFE_TARGET_TOTAL,
        "original_new_api_imports": EXPECTED_NEW_IMPORTS,
        "prior_effective_new_api_imports": FINAL_SAFE_NEW_IMPORTS,
        "effective_new_api_imports": COMPLETE_SAFE_NEW_IMPORTS,
        "total_security_exclusion_count": COMPLETE_SECURITY_EXCLUSION_COUNT,
        "source_preservation": "original_eml_unchanged_local_only",
        "gmail_write_policy": "users.messages.import_only_no_scanning_bypass",
        "blocked_batch_recovery": {
            "batch_sequence": 6,
            "failed_source_id": 103,
            "failed_http_status": 400,
            "gmail_message_id_returned": False,
            "gate_cleared_at": now,
            "pending_before": 1634,
            "pending_after": 1634 - (BODY_PHISHING_EXCLUSION_COUNT - 1),
            "excluded_pending_count": BODY_PHISHING_EXCLUSION_COUNT - 1,
            "unattempted_item_keys_at_recovery": unattempted_item_keys,
            "security_exclusion_source_ids_in_blocked_plan": sorted(
                security_ids_in_plan
            ),
            "verification_gate_before_recovery": archived_gate,
            "failed_source_state_before_recovery": archived_source_103_state,
        },
    }
    checkpoint["verification_gate"] = None
    checkpoint["updated_at"] = now
    write_json_atomic(checkpoint_path, checkpoint)
    counts = status_counts(checkpoint)
    print("body_phishing_security_exclusions_applied:", BODY_PHISHING_EXCLUSION_COUNT)
    print("body_phishing_exclusion_source_ids:", sorted(BODY_PHISHING_EXCLUSION_IDS))
    print("total_security_messages_kept_local_only:", COMPLETE_SECURITY_EXCLUSION_COUNT)
    print("effective_target_gmail_messages:", COMPLETE_SAFE_TARGET_TOTAL)
    print("effective_new_api_imports:", COMPLETE_SAFE_NEW_IMPORTS)
    print("safe_pending_imports:", counts.get("pending", 0))
    print("recovered_blocked_batch: 6")
    print("gmail_writes_this_run: 0")
    return 0


def apply_gmail_rejected_attachment_exclusion(
    checkpoint_path: Path,
    checkpoint: dict[str, Any],
    manifest_sha256: str,
    manifest: dict[str, Any],
    rows: list[dict],
) -> int:
    """Keep source 1857 local-only and clear its exact blocked batch-13 gate."""
    if checkpoint.get("gmail_rejected_attachment_policy") is not None:
        print("gmail_rejected_attachment_exclusion_already_applied: true")
        print("gmail_writes_this_run: 0")
        return 0
    if checkpoint.get("body_phishing_security_policy") is None:
        raise ImportSafetyError("The earlier body-phishing exclusions are not applied.")
    evidence = load_gmail_rejected_attachment_exclusions(rows)
    evidence_item = evidence["items"][0]
    expected_before = Counter(
        {
            "pending": 113,
            "failed": 1,
            "verified": 1783,
            "verified_pilot": 5,
            "skipped_semantic_duplicate": 3,
            "skipped_security_attachment": 20,
            "skipped_security_html_phishing": 14,
            "skipped_security_html_redirect": 4,
            "skipped_security_body_phishing": 62,
        }
    )
    gate = checkpoint.get("verification_gate")
    if (
        checkpoint.get("batch_sequence") != 13
        or not isinstance(gate, dict)
        or gate.get("status") != "blocked"
        or gate.get("batch_sequence") != 13
        or gate.get("item_keys") != []
        or gate.get("source_ids") != []
        or len(gate.get("planned_item_keys", [])) != 250
        or len(set(gate.get("planned_item_keys", []))) != 250
        or len(gate.get("planned_source_ids", [])) != 250
        or len(set(gate.get("planned_source_ids", []))) != 250
        or len(gate.get("verified_completed_item_keys", [])) != 196
        or len(set(gate.get("verified_completed_item_keys", []))) != 196
        or status_counts(checkpoint) != expected_before
    ):
        raise ImportSafetyError(
            "The checkpoint is not the exact post-receipt blocked batch-13 state."
        )
    planned_item_keys = gate["planned_item_keys"]
    planned_source_ids = gate["planned_source_ids"]
    if any(item_key not in checkpoint["states"] for item_key in planned_item_keys) or [
        int(checkpoint["states"][item_key]["source_id"])
        for item_key in planned_item_keys
    ] != [int(source_id) for source_id in planned_source_ids]:
        raise ImportSafetyError("The blocked batch-13 plan no longer reconciles.")

    verified_completed_keys = set(gate["verified_completed_item_keys"])
    batch_thirteen_receipts = [
        receipt
        for receipt in checkpoint.get("verified_batches", [])
        if receipt.get("batch_sequence") == 13
    ]
    if (
        len(batch_thirteen_receipts) != 1
        or batch_thirteen_receipts[0].get("item_count") != 196
        or set(batch_thirteen_receipts[0].get("item_keys", []))
        != verified_completed_keys
        or batch_thirteen_receipts[0].get("verified_at")
        != gate.get("successful_subset_verified_at")
        or batch_thirteen_receipts[0].get("verification_method")
        != "gmail_api_import_response_id_exact_account_after_verified_canary"
        or batch_thirteen_receipts[0].get("verification_receipt")
        != {
            "basis": "unique_gmail_message_id_returned_for_each_request",
            "destination_guard": "exact_oauth_email_match_before_writes",
            "post_import_readback": "not_performed",
        }
    ):
        raise ImportSafetyError(
            "The 196 successful batch-13 receipts no longer match the blocked gate."
        )

    source_state = checkpoint["states"][SOURCE_1857_ITEM_KEY]
    unattempted_item_keys = [
        item_key
        for item_key in planned_item_keys
        if item_key not in verified_completed_keys
        and item_key != SOURCE_1857_ITEM_KEY
    ]
    if (
        evidence_item.get("item_key") != SOURCE_1857_ITEM_KEY
        or SOURCE_1857_ITEM_KEY not in planned_item_keys
        or SOURCE_1857_ITEM_KEY in verified_completed_keys
        or planned_item_keys.index(SOURCE_1857_ITEM_KEY) != 196
        or not verified_completed_keys.issubset(set(planned_item_keys))
        or len(unattempted_item_keys) != 53
        or blocking_states(checkpoint) != [(1857, "failed")]
        or source_state.get("source_id") != 1857
        or source_state.get("source_sha256") != SOURCE_1857_ITEM_KEY
        or source_state.get("message_id") != SOURCE_1857_MESSAGE_ID
        or source_state.get("status") != "failed"
        or source_state.get("http_status") != 400
        or source_state.get("error") != SOURCE_1857_ERROR
        or source_state.get("upload_mode") != "resumable_rfc822"
        or source_state.get("attempted_at") != SOURCE_1857_ATTEMPTED_AT
        or source_state.get("gmail_message_id")
        or source_state.get("imported_at")
    ):
        raise ImportSafetyError(
            "Source 1857 no longer has its exact definite Gmail rejection receipt."
        )
    if any(
        checkpoint["states"][item_key].get("status") != "pending"
        for item_key in unattempted_item_keys
    ):
        raise ImportSafetyError(
            "The blocked batch-13 remainder is no longer exactly 53 pending rows."
        )

    checkpoint_bytes = checkpoint_path.read_bytes()
    checkpoint_sha256 = hashlib.sha256(checkpoint_bytes).hexdigest()
    if checkpoint_sha256 != SOURCE_1857_PRETRANSITION_CHECKPOINT_SHA256:
        raise ImportSafetyError(
            "The source 1857 pretransition checkpoint hash changed."
        )
    backup_path = checkpoint_path.with_name(
        f"checkpoint.pre-source1857-recovery-{checkpoint_sha256[:16]}.json"
    )
    now = utc_now()
    archived_gate = deepcopy(gate)
    archived_failed_state = deepcopy(source_state)
    source_state.update(
        status="skipped_gmail_rejected_attachment",
        security_excluded_at=now,
        security_exclusion_manifest=str(GMAIL_REJECTED_ATTACHMENT_EXCLUSIONS),
        security_exclusion_manifest_sha256=(
            GMAIL_REJECTED_ATTACHMENT_EXCLUSIONS_SHA256
        ),
        security_classification=evidence_item["classification"],
        security_indicators=evidence_item["indicators"],
        attachment_part_index=evidence_item["attachment_part_index"],
        attachment_filename=evidence_item["attachment_filename"],
        attachment_content_type=evidence_item["attachment_content_type"],
        attachment_size_bytes=evidence_item["attachment_size_bytes"],
        attachment_sha256=evidence_item["attachment_sha256"],
        source_preservation=evidence_item["source_preservation"],
        source_preserved_path=str(SOURCE_ROOT / source_state["relative_path"]),
        source_preserved_sha256=source_state["source_sha256"],
        gmail_write_attempted=True,
        gmail_outcome=evidence_item["gmail_outcome_at_detection"],
        status_before_security_exclusion="failed",
    )
    checkpoint["gmail_rejected_attachment_policy"] = {
        "status": "applied",
        "applied_at": now,
        "gmail_rejected_attachment_count": (
            GMAIL_REJECTED_ATTACHMENT_EXCLUSION_COUNT
        ),
        "gmail_rejected_attachment_source_ids": sorted(
            GMAIL_REJECTED_ATTACHMENT_EXCLUSION_IDS
        ),
        "evidence_manifest": str(GMAIL_REJECTED_ATTACHMENT_EXCLUSIONS),
        "evidence_manifest_sha256": GMAIL_REJECTED_ATTACHMENT_EXCLUSIONS_SHA256,
        "original_target_gmail_messages": EXPECTED_TARGET_TOTAL,
        "prior_effective_target_gmail_messages": COMPLETE_SAFE_TARGET_TOTAL,
        "effective_target_gmail_messages": POST_REJECTION_SAFE_TARGET_TOTAL,
        "original_new_api_imports": EXPECTED_NEW_IMPORTS,
        "prior_effective_new_api_imports": COMPLETE_SAFE_NEW_IMPORTS,
        "effective_new_api_imports": POST_REJECTION_SAFE_NEW_IMPORTS,
        "total_local_only_count": COMPLETE_LOCAL_ONLY_COUNT,
        "source_preservation": "original_eml_unchanged_local_only",
        "gmail_write_policy": "users.messages.import_only_no_scanning_bypass",
        "google_rejection_trigger": "not_independently_known",
        "blocked_batch_recovery": {
            "batch_sequence": 13,
            "failed_source_id": 1857,
            "failed_http_status": 400,
            "gmail_message_id_returned": False,
            "gate_cleared_at": now,
            "pending_before": 113,
            "pending_after": 113,
            "excluded_pending_count": 0,
            "successful_subset_item_count": 196,
            "pretransition_checkpoint_sha256": checkpoint_sha256,
            "unattempted_item_keys_at_recovery": unattempted_item_keys,
            "verification_gate_before_recovery": archived_gate,
            "failed_source_state_before_recovery": archived_failed_state,
        },
    }
    checkpoint["verification_gate"] = None
    checkpoint["updated_at"] = now
    descriptor, staged_name = tempfile.mkstemp(
        prefix="checkpoint.source1857-candidate-",
        suffix=".json",
        dir=checkpoint_path.parent,
    )
    os.close(descriptor)
    staged_path = Path(staged_name)
    try:
        write_json_atomic(staged_path, checkpoint)
        validated_checkpoint = load_checkpoint(
            staged_path, manifest_sha256, manifest, rows
        )
        preserve_content_addressed_backup(
            backup_path, checkpoint_bytes, "Source 1857 checkpoint"
        )
        os.replace(staged_path, checkpoint_path)
    finally:
        staged_path.unlink(missing_ok=True)
    counts = status_counts(validated_checkpoint)
    print("gmail_rejected_attachment_exclusions_applied: 1")
    print("gmail_rejected_attachment_source_ids: [1857]")
    print("total_messages_kept_local_only:", COMPLETE_LOCAL_ONLY_COUNT)
    print("effective_target_gmail_messages:", POST_REJECTION_SAFE_TARGET_TOTAL)
    print("effective_new_api_imports:", POST_REJECTION_SAFE_NEW_IMPORTS)
    print("safe_pending_imports:", counts.get("pending", 0))
    print("recovered_blocked_batch: 13")
    print("checkpoint_backup:", backup_path)
    print("checkpoint_backup_sha256:", checkpoint_sha256)
    print("gmail_writes_this_run: 0")
    return 0


def print_summary(checkpoint: dict[str, Any] | None) -> None:
    print("source_files:", SOURCE_COUNT)
    print("source_bytes:", SOURCE_BYTES)
    print("verified_pilot_messages: 5")
    print("semantic_duplicates_skipped: 3")
    print("original_target_gmail_messages:", EXPECTED_TARGET_TOTAL)
    security_applied = bool(
        checkpoint is not None and checkpoint.get("security_attachment_policy")
    )
    html_phishing_applied = bool(
        checkpoint is not None and checkpoint.get("html_phishing_security_policy")
    )
    html_redirect_applied = bool(
        checkpoint is not None and checkpoint.get("html_redirect_security_policy")
    )
    body_phishing_applied = bool(
        checkpoint is not None and checkpoint.get("body_phishing_security_policy")
    )
    gmail_rejected_attachment_applied = bool(
        checkpoint is not None
        and checkpoint.get("gmail_rejected_attachment_policy")
    )
    if gmail_rejected_attachment_applied:
        print("blocked_attachment_security_exclusions:", SECURITY_EXCLUSION_COUNT)
        print(
            "credential_phishing_html_exclusions:",
            HTML_PHISHING_EXCLUSION_COUNT,
        )
        print("redirect_phishing_html_exclusions:", HTML_REDIRECT_EXCLUSION_COUNT)
        print("body_link_phishing_exclusions:", BODY_PHISHING_EXCLUSION_COUNT)
        print(
            "definite_gmail_rejected_attachment_exclusions:",
            GMAIL_REJECTED_ATTACHMENT_EXCLUSION_COUNT,
        )
        print("messages_kept_local_only:", COMPLETE_LOCAL_ONLY_COUNT)
        print("effective_target_gmail_messages:", POST_REJECTION_SAFE_TARGET_TOTAL)
        print("effective_new_api_imports:", POST_REJECTION_SAFE_NEW_IMPORTS)
    elif body_phishing_applied:
        print("blocked_attachment_security_exclusions:", SECURITY_EXCLUSION_COUNT)
        print(
            "credential_phishing_html_exclusions:",
            HTML_PHISHING_EXCLUSION_COUNT,
        )
        print("redirect_phishing_html_exclusions:", HTML_REDIRECT_EXCLUSION_COUNT)
        print("body_link_phishing_exclusions:", BODY_PHISHING_EXCLUSION_COUNT)
        print("security_messages_kept_local_only:", COMPLETE_SECURITY_EXCLUSION_COUNT)
        print("effective_target_gmail_messages:", COMPLETE_SAFE_TARGET_TOTAL)
        print("effective_new_api_imports:", COMPLETE_SAFE_NEW_IMPORTS)
    elif html_redirect_applied:
        print("blocked_attachment_security_exclusions:", SECURITY_EXCLUSION_COUNT)
        print(
            "credential_phishing_html_exclusions:",
            HTML_PHISHING_EXCLUSION_COUNT,
        )
        print("redirect_phishing_html_exclusions:", HTML_REDIRECT_EXCLUSION_COUNT)
        print("security_messages_kept_local_only:", FINAL_SECURITY_EXCLUSION_COUNT)
        print("effective_target_gmail_messages:", FINAL_SAFE_TARGET_TOTAL)
        print("effective_new_api_imports:", FINAL_SAFE_NEW_IMPORTS)
    elif html_phishing_applied:
        print("blocked_attachment_security_exclusions:", SECURITY_EXCLUSION_COUNT)
        print(
            "credential_phishing_html_exclusions:",
            HTML_PHISHING_EXCLUSION_COUNT,
        )
        print(
            "security_messages_kept_local_only:",
            TOTAL_SECURITY_EXCLUSION_COUNT,
        )
        print(
            "effective_target_gmail_messages:",
            SAFE_TARGET_TOTAL_AFTER_HTML_EXCLUSIONS,
        )
        print(
            "effective_new_api_imports:",
            SAFE_NEW_IMPORTS_AFTER_HTML_EXCLUSIONS,
        )
    elif security_applied:
        print("security_attachments_kept_local_only:", SECURITY_EXCLUSION_COUNT)
        print("effective_target_gmail_messages:", EFFECTIVE_TARGET_TOTAL)
        print("effective_new_api_imports:", EFFECTIVE_NEW_IMPORTS)
    else:
        print("planned_new_api_imports:", EXPECTED_NEW_IMPORTS)
    print("source_files_modified: 0")
    if checkpoint is not None:
        counts = status_counts(checkpoint)
        print("checkpoint_status_counts:", json.dumps(dict(sorted(counts.items()))))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--credentials", type=Path, required=True)
    parser.add_argument("--checkpoint", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--execute", action="store_true")
    mode.add_argument("--record-last-batch-verified", action="store_true")
    mode.add_argument("--record-last-batch-api-receipts", action="store_true")
    mode.add_argument("--reconcile-source-954-preflight", action="store_true")
    mode.add_argument("--reconcile-source-1632-readonly", action="store_true")
    mode.add_argument("--apply-security-attachment-exclusions", action="store_true")
    mode.add_argument("--apply-html-phishing-security-exclusions", action="store_true")
    mode.add_argument("--apply-html-redirect-security-exclusions", action="store_true")
    mode.add_argument("--apply-body-phishing-security-exclusions", action="store_true")
    mode.add_argument("--apply-gmail-rejected-attachment-exclusion", action="store_true")
    parser.add_argument("--batch-size", type=int)
    parser.add_argument("--source-1632-evidence", type=Path)
    parser.add_argument("--confirm-destination")
    parser.add_argument("--confirm-new-api-imports", type=int)
    parser.add_argument(
        "--confirm-baseline-had-no-preexisting-archive-copies", action="store_true"
    )
    parser.add_argument("--confirm-storage-at-least-1-3-gb", action="store_true")
    parser.add_argument("--confirm-semantic-duplicate-skips", type=int)
    parser.add_argument(
        "--confirm-last-batch-searches-exactly-one", action="store_true"
    )
    parser.add_argument(
        "--confirm-keep-security-attachments-local-only", action="store_true"
    )
    parser.add_argument("--confirm-keep-html-phishing-local-only", action="store_true")
    parser.add_argument("--confirm-keep-html-redirects-local-only", action="store_true")
    parser.add_argument("--confirm-keep-body-phishing-local-only", action="store_true")
    parser.add_argument("--confirm-keep-source-1857-local-only", action="store_true")
    args = parser.parse_args()

    try:
        if args.checkpoint.resolve() != CANONICAL_CHECKPOINT.resolve():
            raise ImportSafetyError("Checkpoint path is not canonical.")
        validate_credentials(args.credentials)
        manifest = load_json(args.manifest)
        rows = validate_manifest_header(manifest, args.manifest)
        manifest_sha256 = sha256_file(args.manifest)
        if (
            not args.execute
            and not args.record_last_batch_verified
            and not args.record_last_batch_api_receipts
            and not args.reconcile_source_954_preflight
            and not args.reconcile_source_1632_readonly
            and not args.apply_security_attachment_exclusions
            and not args.apply_html_phishing_security_exclusions
            and not args.apply_html_redirect_security_exclusions
            and not args.apply_body_phishing_security_exclusions
            and not args.apply_gmail_rejected_attachment_exclusion
        ):
            validate_source_snapshot(rows)
            checkpoint = None
            if args.checkpoint.exists():
                checkpoint = load_checkpoint(
                    args.checkpoint, manifest_sha256, manifest, rows
                )
            print_summary(checkpoint)
            print("offline_validation: PASS")
            print("gmail_writes_this_run: 0")
            return 0

        if (args.confirm_destination or "").strip().lower() != DESTINATION:
            raise ImportSafetyError(
                'This action requires --confirm-destination example-bd677ecc@example.org'
            )

        if args.record_last_batch_verified:
            if not args.confirm_last_batch_searches_exactly_one:
                raise ImportSafetyError(
                    "Confirm the last-batch Gmail searches returned exactly one result each."
                )
            if not args.checkpoint.exists():
                raise ImportSafetyError("No full-import checkpoint exists to verify.")
            with exclusive_checkpoint_lock(args.checkpoint):
                validate_source_snapshot(rows)
                checkpoint = load_checkpoint(
                    args.checkpoint, manifest_sha256, manifest, rows
                )
                if recover_empty_collecting_gate(args.checkpoint, checkpoint):
                    print("gmail_writes_this_run: 0")
                    return 0
                return record_last_batch_verified(args.checkpoint, checkpoint)

        if args.record_last_batch_api_receipts:
            if not args.checkpoint.exists():
                raise ImportSafetyError("No full-import checkpoint exists to verify.")
            with exclusive_checkpoint_lock(args.checkpoint):
                validate_source_snapshot(rows)
                checkpoint = load_checkpoint(
                    args.checkpoint, manifest_sha256, manifest, rows
                )
                blockers = blocking_states(checkpoint)
                if any(status != "failed" for _, status in blockers):
                    raise ImportSafetyError(
                        "Only definite failed rows may remain while accepting API receipts."
                    )
                canary_receipts = [
                    receipt
                    for receipt in checkpoint.get("verified_batches", [])
                    if receipt.get("batch_sequence") == 1
                    and receipt.get("item_count") == 25
                    and receipt.get("verification_method")
                    == "gmail_ui_rfc822msgid_and_content_sample"
                ]
                if len(canary_receipts) != 1:
                    raise ImportSafetyError(
                        "The manually verified 25-message canary receipt is missing."
                    )
                return record_last_batch_verified(
                    args.checkpoint,
                    checkpoint,
                    verification_method=(
                        "gmail_api_import_response_id_exact_account_"
                        "after_verified_canary"
                    ),
                    verification_receipt={
                        "basis": "unique_gmail_message_id_returned_for_each_request",
                        "destination_guard": "exact_oauth_email_match_before_writes",
                        "post_import_readback": "not_performed",
                    },
                )

        if args.reconcile_source_954_preflight:
            if not args.checkpoint.exists():
                raise ImportSafetyError("No full-import checkpoint exists to reconcile.")
            with exclusive_checkpoint_lock(args.checkpoint):
                validate_source_snapshot(rows)
                checkpoint = load_checkpoint(
                    args.checkpoint, manifest_sha256, manifest, rows
                )
                return reconcile_source_954_preflight_failure(
                    args.checkpoint, checkpoint, rows
                )

        if args.reconcile_source_1632_readonly:
            if not args.source_1632_evidence:
                raise ImportSafetyError(
                    "Source 1632 reconciliation requires --source-1632-evidence."
                )
            if not args.source_1632_evidence.exists():
                raise ImportSafetyError("Source 1632 evidence file does not exist.")
            if not args.checkpoint.exists():
                raise ImportSafetyError("No full-import checkpoint exists to reconcile.")
            with exclusive_checkpoint_lock(args.checkpoint):
                validate_source_snapshot(rows)
                checkpoint = load_checkpoint(
                    args.checkpoint, manifest_sha256, manifest, rows
                )
                return reconcile_source_1632_readonly_evidence(
                    args.checkpoint,
                    checkpoint,
                    rows,
                    args.source_1632_evidence,
                )

        if args.apply_security_attachment_exclusions:
            if not args.confirm_keep_security_attachments_local_only:
                raise ImportSafetyError(
                    "Confirm that the 20 security-attachment messages stay local-only."
                )
            if not args.checkpoint.exists():
                raise ImportSafetyError("No full-import checkpoint exists to reconcile.")
            with exclusive_checkpoint_lock(args.checkpoint):
                validate_source_snapshot(rows)
                checkpoint = load_checkpoint(
                    args.checkpoint, manifest_sha256, manifest, rows
                )
                return apply_security_attachment_exclusions(
                    args.checkpoint, checkpoint, rows
                )

        if args.apply_html_phishing_security_exclusions:
            if not args.confirm_keep_html_phishing_local_only:
                raise ImportSafetyError(
                    "Confirm that the 14 credential-phishing messages stay local-only."
                )
            if not args.checkpoint.exists():
                raise ImportSafetyError("No full-import checkpoint exists to reconcile.")
            with exclusive_checkpoint_lock(args.checkpoint):
                validate_source_snapshot(rows)
                checkpoint = load_checkpoint(
                    args.checkpoint, manifest_sha256, manifest, rows
                )
                return apply_html_phishing_security_exclusions(
                    args.checkpoint, checkpoint, rows
                )

        if args.apply_html_redirect_security_exclusions:
            if not args.confirm_keep_html_redirects_local_only:
                raise ImportSafetyError(
                    "Confirm that the four HTML redirect lures stay local-only."
                )
            if not args.checkpoint.exists():
                raise ImportSafetyError("No full-import checkpoint exists to reconcile.")
            with exclusive_checkpoint_lock(args.checkpoint):
                validate_source_snapshot(rows)
                checkpoint = load_checkpoint(
                    args.checkpoint, manifest_sha256, manifest, rows
                )
                return apply_html_redirect_security_exclusions(
                    args.checkpoint, checkpoint, rows
                )

        if args.apply_body_phishing_security_exclusions:
            if not args.confirm_keep_body_phishing_local_only:
                raise ImportSafetyError(
                    "Confirm that the body-link phishing messages stay local-only."
                )
            if not args.checkpoint.exists():
                raise ImportSafetyError("No full-import checkpoint exists to reconcile.")
            with exclusive_checkpoint_lock(args.checkpoint):
                validate_source_snapshot(rows)
                checkpoint = load_checkpoint(
                    args.checkpoint, manifest_sha256, manifest, rows
                )
                return apply_body_phishing_security_exclusions(
                    args.checkpoint, checkpoint, rows
                )

        if args.apply_gmail_rejected_attachment_exclusion:
            if not args.confirm_keep_source_1857_local_only:
                raise ImportSafetyError(
                    "Confirm that source 1857 stays unchanged and local-only."
                )
            if not args.checkpoint.exists():
                raise ImportSafetyError("No full-import checkpoint exists to reconcile.")
            with exclusive_checkpoint_lock(args.checkpoint):
                validate_source_snapshot(rows)
                checkpoint = load_checkpoint(
                    args.checkpoint, manifest_sha256, manifest, rows
                )
                return apply_gmail_rejected_attachment_exclusion(
                    args.checkpoint,
                    checkpoint,
                    manifest_sha256,
                    manifest,
                    rows,
                )

        existing_checkpoint = (
            load_json(args.checkpoint) if args.checkpoint.exists() else None
        )
        if isinstance(existing_checkpoint, dict) and existing_checkpoint.get(
            "gmail_rejected_attachment_policy"
        ):
            expected_confirmed_imports = POST_REJECTION_SAFE_NEW_IMPORTS
        elif isinstance(existing_checkpoint, dict) and existing_checkpoint.get(
            "body_phishing_security_policy"
        ):
            expected_confirmed_imports = COMPLETE_SAFE_NEW_IMPORTS
        elif isinstance(existing_checkpoint, dict) and existing_checkpoint.get(
            "html_redirect_security_policy"
        ):
            expected_confirmed_imports = FINAL_SAFE_NEW_IMPORTS
        elif isinstance(existing_checkpoint, dict) and existing_checkpoint.get(
            "html_phishing_security_policy"
        ):
            expected_confirmed_imports = SAFE_NEW_IMPORTS_AFTER_HTML_EXCLUSIONS
        elif isinstance(existing_checkpoint, dict) and existing_checkpoint.get(
            "security_attachment_policy"
        ):
            expected_confirmed_imports = EFFECTIVE_NEW_IMPORTS
        else:
            expected_confirmed_imports = EXPECTED_NEW_IMPORTS
        if args.confirm_new_api_imports != expected_confirmed_imports:
            raise ImportSafetyError(
                "Execution requires --confirm-new-api-imports "
                f"{expected_confirmed_imports}."
            )
        if args.batch_size is None or not 1 <= args.batch_size <= MAX_BATCH_SIZE:
            raise ImportSafetyError("--batch-size must be between 1 and 250.")

        with exclusive_checkpoint_lock(args.checkpoint):
            # Hold the lock during the complete source audit as well as OAuth and
            # writes. Two commands started together therefore cannot consume two
            # successive batches from the same checkpoint.
            validate_source_snapshot(rows)
            if args.checkpoint.exists():
                checkpoint = load_checkpoint(
                    args.checkpoint, manifest_sha256, manifest, rows
                )
            else:
                if not args.confirm_baseline_had_no_preexisting_archive_copies:
                    raise ImportSafetyError(
                        "Confirm the destination baseline had no preexisting archive copies."
                    )
                if not args.confirm_storage_at_least_1_3_gb:
                    raise ImportSafetyError(
                        "Confirm at least 1.3 GB of destination storage is available."
                    )
                if args.confirm_semantic_duplicate_skips != 3:
                    raise ImportSafetyError(
                        "Confirm the reviewed policy to skip three semantic duplicate copies."
                    )
                checkpoint = load_checkpoint(
                    args.checkpoint,
                    manifest_sha256,
                    manifest,
                    rows,
                    initial_confirmations={
                        "baseline_had_no_preexisting_archive_copies": True,
                        "semantic_duplicate_skips": 3,
                        "storage_at_least_1_3_gb": True,
                    },
                )
            recover_empty_collecting_gate(args.checkpoint, checkpoint)
            blocked = blocking_states(checkpoint)
            if blocked:
                raise ImportSafetyError(
                    f"Checkpoint has blocking states that need reconciliation: {blocked[:10]}"
                )
            if checkpoint.get("verification_gate") is not None:
                raise ImportSafetyError(
                    "The previous batch must be verified and recorded before another batch."
                )
            validation_batch_size = required_validation_batch_size(checkpoint, rows)
            if (
                validation_batch_size is not None
                and args.batch_size != validation_batch_size
            ):
                raise ImportSafetyError(
                    "The validation phase requires a batch of exactly "
                    f"{validation_batch_size} remaining canary messages."
                )
            print_summary(checkpoint)
            write_json_atomic(args.checkpoint, checkpoint)
            credentials = authorize(args.credentials)
            print("authorized_email:", DESTINATION)
            print("exact_account_match: true")
            return import_batch(
                credentials,
                rows,
                args.checkpoint,
                checkpoint,
                args.batch_size,
            )
    except (ImportSafetyError, ArchiveError) as exc:
        print(f"STOPPED: {exc}", file=sys.stderr)
        print("No further messages were imported by this run.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit("Archived reference variant. Use the configurable v2 engine at the repository root.")
    raise SystemExit(main())
