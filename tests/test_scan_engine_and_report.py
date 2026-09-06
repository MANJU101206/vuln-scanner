import json
import os
import tempfile
import unittest

from vuln_scanner.report import build_report_data, generate_html_report, generate_json_report, generate_markdown_report
from vuln_scanner.scan_engine import parse_port_range, service_name_for_port


class TestParsePortRange(unittest.TestCase):
    def test_default_returns_common_ports(self):
        ports = parse_port_range(None)
        self.assertIn(22, ports)
        self.assertIn(443, ports)

    def test_range_syntax(self):
        self.assertEqual(parse_port_range("20-23"), [20, 21, 22, 23])

    def test_list_syntax(self):
        self.assertEqual(parse_port_range("22,80,443"), [22, 80, 443])

    def test_single_port(self):
        self.assertEqual(parse_port_range("8080"), [8080])


class TestServiceName(unittest.TestCase):
    def test_known_port(self):
        self.assertEqual(service_name_for_port(22), "SSH")

    def test_unknown_port(self):
        self.assertEqual(service_name_for_port(9999), "Unknown")


_SAMPLE_RESULTS = [
    {
        "port": 22,
        "service": "SSH",
        "product": "OpenSSH",
        "version": "7.4",
        "banner": "SSH-2.0-OpenSSH_7.4",
        "tls": None,
        "cves": [],
        "findings": [("High", "OpenSSH 7.0-7.4 has known vulnerabilities.")],
    },
    {
        "port": 443,
        "service": "HTTPS",
        "product": "Apache",
        "version": "2.4.49",
        "banner": "HTTP/1.1 200 OK",
        "tls": {"negotiated_protocol": "TLSv1.2"},
        "cves": [{
            "id": "CVE-2021-41773", "description": "Path traversal.", "cvss_score": 9.8,
            "cvss_version": "3.1", "severity": "Critical",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
        }],
        "findings": [("Critical", "CVE-2021-41773: Path traversal.")],
    },
]


class TestBuildReportData(unittest.TestCase):
    def test_severity_counts_and_ordering(self):
        data = build_report_data("example.com", _SAMPLE_RESULTS)
        self.assertEqual(data["severity_summary"]["Critical"], 1)
        self.assertEqual(data["severity_summary"]["High"], 1)
        self.assertEqual(data["findings"][0]["severity"], "Critical")

    def test_open_port_count(self):
        data = build_report_data("example.com", _SAMPLE_RESULTS)
        self.assertEqual(data["open_port_count"], 2)


class TestReportGenerators(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def test_json_report_round_trips(self):
        path = os.path.join(self.tmpdir, "report.json")
        text, counts = generate_json_report("example.com", _SAMPLE_RESULTS, path)
        parsed = json.loads(text)
        self.assertEqual(parsed["target"], "example.com")
        self.assertEqual(counts["Critical"], 1)
        with open(path) as f:
            self.assertEqual(json.load(f)["target"], "example.com")

    def test_markdown_report_contains_expected_sections(self):
        path = os.path.join(self.tmpdir, "report.md")
        text, _counts = generate_markdown_report("example.com", _SAMPLE_RESULTS, path)
        self.assertIn("# Vulnerability Scan Report", text)
        self.assertIn("## CVE Details", text)
        self.assertIn("CVE-2021-41773", text)

    def test_html_report_escapes_and_contains_data(self):
        path = os.path.join(self.tmpdir, "report.html")
        text, _counts = generate_html_report("example.com", _SAMPLE_RESULTS, path)
        self.assertIn("<html", text)
        self.assertIn("example.com", text)
        self.assertIn("CVE-2021-41773", text)

    def test_empty_results_still_produce_valid_report(self):
        path = os.path.join(self.tmpdir, "empty.md")
        text, counts = generate_markdown_report("example.com", [], path)
        self.assertIn("No findings to report.", text)
        self.assertEqual(sum(counts.values()), 0)


if __name__ == "__main__":
    unittest.main()
