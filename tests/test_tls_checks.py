import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from vuln_scanner.tls_checks import check_certificate


class TestCheckCertificate(unittest.TestCase):
    def _cert_info(self, days_until_expiry, self_signed=False):
        return {
            "self_signed": self_signed,
            "days_until_expiry": days_until_expiry,
            "not_after": (datetime.now(timezone.utc) + timedelta(days=days_until_expiry)).isoformat(),
            "subject": "example.com",
            "issuer": "example.com" if self_signed else "Let's Encrypt",
        }

    @patch("vuln_scanner.tls_checks.get_certificate_info")
    def test_expired_certificate_is_critical(self, mock_info):
        mock_info.return_value = self._cert_info(-5)
        findings = check_certificate("example.com", 443)
        self.assertTrue(any(sev == "Critical" for sev, _desc in findings))

    @patch("vuln_scanner.tls_checks.get_certificate_info")
    def test_soon_to_expire_certificate_is_high(self, mock_info):
        mock_info.return_value = self._cert_info(5)
        findings = check_certificate("example.com", 443)
        self.assertTrue(any(sev == "High" for sev, _desc in findings))

    @patch("vuln_scanner.tls_checks.get_certificate_info")
    def test_healthy_certificate_has_no_expiry_finding(self, mock_info):
        mock_info.return_value = self._cert_info(200)
        findings = check_certificate("example.com", 443)
        self.assertFalse(any("expire" in desc for _sev, desc in findings))

    @patch("vuln_scanner.tls_checks.get_certificate_info")
    def test_self_signed_certificate_flagged(self, mock_info):
        mock_info.return_value = self._cert_info(200, self_signed=True)
        findings = check_certificate("example.com", 443)
        self.assertTrue(any("self-signed" in desc for _sev, desc in findings))

    @patch("vuln_scanner.tls_checks.get_certificate_info", return_value=None)
    def test_unreachable_certificate_returns_no_findings(self, mock_info):
        self.assertEqual(check_certificate("example.com", 443), [])


if __name__ == "__main__":
    unittest.main()
