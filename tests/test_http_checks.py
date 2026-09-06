import unittest

from vuln_scanner.http_checks import check_security_headers
from vuln_scanner.network import parse_http_headers


class TestParseHttpHeaders(unittest.TestCase):
    def test_parses_status_and_headers(self):
        raw = "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html\r\n\r\n<html></html>"
        status, headers, body = parse_http_headers(raw)
        self.assertEqual(status, "HTTP/1.1 200 OK")
        self.assertEqual(headers["Server"], "nginx/1.18.0")
        self.assertEqual(body, "<html></html>")

    def test_empty_input_returns_empty(self):
        status, headers, body = parse_http_headers("")
        self.assertEqual(status, "")
        self.assertEqual(headers, {})
        self.assertEqual(body, "")


class TestCheckSecurityHeaders(unittest.TestCase):
    def test_flags_all_missing_headers(self):
        findings = check_security_headers({"Server": "nginx"})
        described = " ".join(desc for _sev, desc in findings)
        self.assertIn("Strict-Transport-Security", described)
        self.assertIn("Content-Security-Policy", described)

    def test_no_findings_when_all_headers_present(self):
        headers = {
            "Strict-Transport-Security": "max-age=63072000",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'self'",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
        }
        findings = check_security_headers(headers)
        self.assertEqual(findings, [])

    def test_flags_unsafe_inline_csp(self):
        headers = {
            "Strict-Transport-Security": "max-age=1",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'self' 'unsafe-inline'",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
        }
        findings = check_security_headers(headers)
        self.assertTrue(any("unsafe-inline" in desc for _sev, desc in findings))

    def test_flags_version_disclosing_server_header(self):
        headers = {"Server": "Apache/2.4.49"}
        findings = check_security_headers(headers)
        self.assertTrue(any("discloses version" in desc for _sev, desc in findings))

    def test_case_insensitive_header_matching(self):
        headers = {"strict-transport-security": "max-age=1", "x-frame-options": "DENY",
                   "x-content-type-options": "nosniff", "content-security-policy": "default-src 'self'",
                   "referrer-policy": "no-referrer", "permissions-policy": "geolocation=()"}
        findings = check_security_headers(headers)
        self.assertEqual(findings, [])

    def test_empty_headers_returns_empty(self):
        self.assertEqual(check_security_headers({}), [])


if __name__ == "__main__":
    unittest.main()
