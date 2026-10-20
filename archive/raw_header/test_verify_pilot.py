# Sanitized historical reference: source-specific evidence and live configuration are not distributed.
"""Pure MIME tests only; these never invoke main or access Gmail."""

import unittest

from verify_pilot import inventory_issues, mime_inventory


class FidelityTests(unittest.TestCase):
    def test_transport_headers_do_not_affect_content_check(self):
        source = b"Content-Type: text/plain; charset=utf-8\r\n\r\nhello\r\n"
        remote = b"Received: by gmail.invalid\r\nX-Imported: yes\r\n" + source
        self.assertEqual(inventory_issues(mime_inventory(source), mime_inventory(remote)), [])

    def test_equivalent_transfer_encoding_preserves_decoded_bytes(self):
        source = b"Content-Type: text/plain\r\n\r\nhello"
        remote = b"Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\naGVsbG8="
        self.assertEqual(inventory_issues(mime_inventory(source), mime_inventory(remote)), [])

    def test_changed_payload_is_rejected(self):
        source = b"Content-Type: text/plain\r\n\r\nhello"
        remote = b"Content-Type: text/plain\r\n\r\njello"
        self.assertIn("leaves[0].decoded_sha256_mismatch", inventory_issues(mime_inventory(source), mime_inventory(remote)))

    def test_attachment_identity_changes_are_rejected(self):
        source = b"Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=a.bin\r\nContent-ID: <one>\r\n\r\nhello"
        remote = source.replace(b"a.bin", b"b.bin").replace(b"<one>", b"<two>")
        issues = inventory_issues(mime_inventory(source), mime_inventory(remote))
        self.assertIn("leaves[0].filename_mismatch", issues)
        self.assertIn("leaves[0].content_id_mismatch", issues)


if __name__ == "__main__":
    raise SystemExit("Archived reference variant. Use the configurable v2 engine at the repository root.")
    unittest.main()
