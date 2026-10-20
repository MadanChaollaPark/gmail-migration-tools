# Sanitized historical reference: source-specific evidence and live configuration are not distributed.
"""Offline tests of the pilot's exact-receipt content comparison."""

import unittest

import verify_pilot as verifier


ATTACHED_MESSAGE = (
    b"Content-Type: message/rfc822\r\n"
    b"Content-Disposition: attachment\r\n\r\n"
    b"From: inner@example.org\r\nTo: reader@example.org\r\n"
    b"Subject: inner subject\r\nMessage-ID: <inner@example.org>\r\n"
    b"Content-Type: text/plain; charset=us-ascii\r\n\r\nInner body"
)
SECOND_PART = b"Content-Type: text/plain; charset=us-ascii\r\n\r\nSecond body"


def fixture(parts=(ATTACHED_MESSAGE, SECOND_PART)):
    return (
        b"From: outer@example.org\r\nTo: recipient@example.org\r\n"
        b"Subject: outer subject\r\nMIME-Version: 1.0\r\n"
        b'Content-Type: multipart/mixed; boundary="outer-boundary"\r\n\r\n'
        b"Preserved preamble\r\n--outer-boundary\r\n"
        + b"\r\n--outer-boundary\r\n".join(parts)
        + b"\r\n--outer-boundary--\r\nPreserved epilogue\r\n"
    )


class MimeInventoryTests(unittest.TestCase):
    def issues(self, observed):
        return verifier.inventory_issues(verifier.mime_inventory(fixture()), verifier.mime_inventory(observed))

    def test_nested_message_headers_are_protected(self):
        issues = self.issues(fixture().replace(b"Subject: inner subject", b"Subject: altered inner subject"))
        self.assertTrue(any("protected_headers_sha256" in item for item in issues))

    def test_decoded_body_changes_are_detected(self):
        issues = self.issues(fixture().replace(b"Inner body", b"Altered body"))
        self.assertTrue(any("decoded_sha256" in item for item in issues))

    def test_tree_reordering_is_detected(self):
        issues = self.issues(fixture((SECOND_PART, ATTACHED_MESSAGE)))
        self.assertTrue(issues)
        source_paths = [part["path"] for part in verifier.mime_inventory(fixture())["parts"]]
        self.assertEqual(source_paths, [[], [0], [0, 0], [1]])

    def test_extra_top_level_transport_headers_are_allowed(self):
        self.assertEqual(self.issues(b"Received: by gmail.example; fixture\r\nX-Transport-Fixture: added\r\n" + fixture()), [])

    def test_multipart_framing_text_is_protected(self):
        for field in (b"preamble", b"epilogue"):
            with self.subTest(field=field):
                self.assertTrue(self.issues(fixture().replace(b"Preserved " + field, b"Changed " + field)))


if __name__ == "__main__":
    raise SystemExit("Archived reference variant. Use the configurable v2 engine at the repository root.")
    unittest.main()
