import unittest

from vuln_scanner.cvss import best_cvss_from_metrics, severity_from_cvss


class TestSeverityFromCvss(unittest.TestCase):
    def test_critical_band(self):
        self.assertEqual(severity_from_cvss(9.8), "Critical")
        self.assertEqual(severity_from_cvss(9.0), "Critical")
        self.assertEqual(severity_from_cvss(10.0), "Critical")

    def test_high_band(self):
        self.assertEqual(severity_from_cvss(7.5), "High")
        self.assertEqual(severity_from_cvss(8.9), "High")

    def test_medium_band(self):
        self.assertEqual(severity_from_cvss(5.0), "Medium")

    def test_low_band(self):
        self.assertEqual(severity_from_cvss(1.0), "Low")
        self.assertEqual(severity_from_cvss(3.9), "Low")

    def test_zero_is_info(self):
        self.assertEqual(severity_from_cvss(0.0), "Info")

    def test_none_is_info(self):
        self.assertEqual(severity_from_cvss(None), "Info")

    def test_non_numeric_is_info(self):
        self.assertEqual(severity_from_cvss("not-a-score"), "Info")


class TestBestCvssFromMetrics(unittest.TestCase):
    def test_prefers_v31_over_v30_and_v2(self):
        metrics = {
            "cvssMetricV2": [{"cvssData": {"baseScore": 5.0, "vectorString": "AV:N"}}],
            "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "vectorString": "CVSS:3.1/..."}}],
        }
        score, version, vector = best_cvss_from_metrics(metrics)
        self.assertEqual(score, 9.8)
        self.assertEqual(version, "3.1")

    def test_falls_back_to_v2_when_v3_absent(self):
        metrics = {"cvssMetricV2": [{"cvssData": {"baseScore": 5.0, "vectorString": "AV:N"}}]}
        score, version, vector = best_cvss_from_metrics(metrics)
        self.assertEqual(score, 5.0)
        self.assertEqual(version, "2.0")

    def test_empty_metrics_returns_none(self):
        self.assertEqual(best_cvss_from_metrics({}), (None, None, None))
        self.assertEqual(best_cvss_from_metrics(None), (None, None, None))


if __name__ == "__main__":
    unittest.main()
