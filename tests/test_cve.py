import json
import unittest
import urllib.error
from unittest.mock import patch

from vuln_scanner.cve import CveClient


def _fake_nvd_response(cve_id="CVE-2021-41773", score=9.8, version="3.1"):
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "descriptions": [{"lang": "en", "value": "A path traversal vulnerability."}],
                    "metrics": {
                        "cvssMetricV31": [{"cvssData": {"baseScore": score, "vectorString": "CVSS:3.1/AV:N"}}]
                    },
                }
            }
        ]
    }
    return json.dumps(payload).encode()


class _FakeResponse:
    def __init__(self, data):
        self._data = data

    def read(self):
        return self._data

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class TestCveClient(unittest.TestCase):
    def setUp(self):
        self.tmp_cache = "/tmp/vuln_scanner_test_cache.json"

    def tearDown(self):
        import os
        if os.path.exists(self.tmp_cache):
            os.remove(self.tmp_cache)

    @patch("vuln_scanner.cve.urllib.request.urlopen")
    def test_lookup_parses_live_nvd_response(self, mock_urlopen):
        mock_urlopen.return_value = _FakeResponse(_fake_nvd_response())
        client = CveClient(cache_path=self.tmp_cache)
        results = client.lookup("Apache", "2.4.49")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["id"], "CVE-2021-41773")
        self.assertEqual(results[0]["severity"], "Critical")

    @patch("vuln_scanner.cve.urllib.request.urlopen")
    def test_lookup_caches_result_to_avoid_repeat_calls(self, mock_urlopen):
        mock_urlopen.return_value = _FakeResponse(_fake_nvd_response())
        client = CveClient(cache_path=self.tmp_cache)
        client.lookup("Apache", "2.4.49")
        client.lookup("Apache", "2.4.49")
        self.assertEqual(mock_urlopen.call_count, 1)

    @patch("vuln_scanner.cve.urllib.request.urlopen", side_effect=urllib.error.URLError("no network"))
    def test_lookup_falls_back_to_offline_db_on_network_error(self, mock_urlopen):
        client = CveClient(cache_path=self.tmp_cache)
        results = client.lookup("vsftpd", "2.3.4")
        self.assertTrue(any(r["id"] == "CVE-2011-2523" for r in results))

    def test_offline_mode_skips_network_entirely(self):
        client = CveClient(cache_path=self.tmp_cache, offline=True)
        with patch("vuln_scanner.cve.urllib.request.urlopen") as mock_urlopen:
            results = client.lookup("vsftpd", "2.3.4")
            mock_urlopen.assert_not_called()
        self.assertTrue(any(r["id"] == "CVE-2011-2523" for r in results))

    def test_lookup_unknown_product_returns_empty_offline(self):
        client = CveClient(cache_path=self.tmp_cache, offline=True)
        self.assertEqual(client.lookup("TotallyMadeUpProduct", "1.0"), [])

    def test_lookup_with_no_product_returns_empty(self):
        client = CveClient(cache_path=self.tmp_cache, offline=True)
        self.assertEqual(client.lookup(None, "1.0"), [])


if __name__ == "__main__":
    unittest.main()
