"""
CVE / NVD integration.

Looks up known CVEs for a detected (product, version) pair using the NIST
NVD CVE 2.0 REST API (https://nvd.nist.gov/developers/vulnerabilities),
with:

  * on-disk JSON caching, keyed by product+version, so repeat scans (and
    test runs) don't hammer the API,
  * basic client-side rate limiting to respect NVD's public limits
    (5 requests / 30s without an API key, 50 / 30s with one),
  * a small built-in offline database used automatically if the network
    is unavailable, a lookup fails, or `--no-cve` / `offline=True` is set.

An NVD API key can be supplied via the `NVD_API_KEY` environment variable
or passed explicitly; it raises the rate limit but is not required.
"""

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from .config import NVD_API_BASE
from .cvss import best_cvss_from_metrics, severity_from_cvss

DEFAULT_CACHE_PATH = Path.home() / ".cache" / "vuln_scanner" / "nvd_cache.json"

# Minimal illustrative offline fallback, used when NVD can't be reached.
# Not a substitute for the live feed -- see README.
OFFLINE_CVE_DB = {
    "vsftpd 2.3.4": [
        {"id": "CVE-2011-2523", "description": "vsftpd 2.3.4 contains a backdoor allowing remote command execution.",
         "cvss_score": 10.0, "cvss_version": "2.0", "severity": "Critical",
         "url": "https://nvd.nist.gov/vuln/detail/CVE-2011-2523"},
    ],
    "openssh 7.2": [
        {"id": "CVE-2016-6210", "description": "OpenSSH before 7.3 allows remote user enumeration via timing differences.",
         "cvss_score": 5.0, "cvss_version": "2.0", "severity": "Medium",
         "url": "https://nvd.nist.gov/vuln/detail/CVE-2016-6210"},
    ],
    "apache 2.4.49": [
        {"id": "CVE-2021-41773", "description": "Path traversal and RCE in Apache HTTP Server 2.4.49.",
         "cvss_score": 9.8, "cvss_version": "3.1", "severity": "Critical",
         "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"},
    ],
    "apache 2.4.50": [
        {"id": "CVE-2021-42013", "description": "Incomplete fix for CVE-2021-41773 in Apache HTTP Server 2.4.50, allows path traversal/RCE.",
         "cvss_score": 9.8, "cvss_version": "3.1", "severity": "Critical",
         "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-42013"},
    ],
}


class RateLimiter:
    """Simple sliding-window client-side rate limiter for NVD API calls."""

    def __init__(self, max_calls, period_seconds):
        self.max_calls = max_calls
        self.period_seconds = period_seconds
        self._calls = []

    def wait(self):
        now = time.monotonic()
        self._calls = [t for t in self._calls if now - t < self.period_seconds]
        if len(self._calls) >= self.max_calls:
            sleep_for = self.period_seconds - (now - self._calls[0])
            if sleep_for > 0:
                time.sleep(sleep_for)
        self._calls.append(time.monotonic())


class CveClient:
    """Client for looking up CVEs by product/version, with caching."""

    def __init__(self, api_key=None, cache_path=None, offline=False, timeout=10):
        self.api_key = api_key or os.environ.get("NVD_API_KEY")
        self.cache_path = Path(cache_path) if cache_path else DEFAULT_CACHE_PATH
        self.offline = offline
        self.timeout = timeout
        # NVD limits: 5/30s without key, 50/30s with key.
        self._limiter = RateLimiter(45 if self.api_key else 4, 30)
        self._cache = self._load_cache()

    def _load_cache(self):
        try:
            if self.cache_path.exists():
                return json.loads(self.cache_path.read_text())
        except (OSError, json.JSONDecodeError):
            pass
        return {}

    def _save_cache(self):
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.cache_path.write_text(json.dumps(self._cache, indent=2))
        except OSError:
            pass

    @staticmethod
    def _cache_key(product, version):
        return f"{product.strip().lower()} {(version or '').strip()}".strip()

    def lookup(self, product, version=None, max_results=5):
        """
        Return a list of CVE dicts: id, description, cvss_score,
        cvss_version, severity, url -- for the given product/version.
        """
        if not product:
            return []
        key = self._cache_key(product, version)

        if key in self._cache:
            return self._cache[key]

        if self.offline:
            return self._offline_lookup(key)

        try:
            results = self._query_nvd(product, version, max_results)
            self._cache[key] = results
            self._save_cache()
            return results
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError, ValueError):
            # Network unavailable, rate-limited, or malformed response --
            # degrade gracefully to the small offline reference set.
            return self._offline_lookup(key)

    def _offline_lookup(self, key):
        return OFFLINE_CVE_DB.get(key, [])

    def _query_nvd(self, product, version, max_results):
        keyword = f"{product} {version}".strip() if version else product
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": str(max_results),
        }
        url = f"{NVD_API_BASE}?{urllib.parse.urlencode(params)}"

        headers = {"User-Agent": "vuln-scanner/2.0 (educational)"}
        if self.api_key:
            headers["apiKey"] = self.api_key

        self._limiter.wait()
        request = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            payload = json.loads(response.read().decode())

        return self._parse_nvd_response(payload)

    @staticmethod
    def _parse_nvd_response(payload):
        results = []
        for item in payload.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            descriptions = cve.get("descriptions", [])
            description = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"),
                descriptions[0]["value"] if descriptions else "",
            )
            score, cvss_version, vector = best_cvss_from_metrics(cve.get("metrics", {}))
            results.append({
                "id": cve_id,
                "description": description,
                "cvss_score": score,
                "cvss_version": cvss_version,
                "cvss_vector": vector,
                "severity": severity_from_cvss(score),
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else None,
            })
        results.sort(key=lambda c: (c["cvss_score"] or 0), reverse=True)
        return results
