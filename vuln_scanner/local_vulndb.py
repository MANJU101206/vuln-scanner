"""
Small, illustrative local database of known-outdated version patterns.

This complements (not replaces) the live NVD lookup in `cve.py`: it fires
instantly, works fully offline, and catches a few well-known cases even
when a live CVE lookup returns nothing (e.g. keyword search misses).
"""

import re

VULN_DB = {
    "OpenSSH": [
        (r"^[1-6]\.", "Critical", "OpenSSH version predates 7.x -- multiple known CVEs (e.g. CVE-2016-0777)."),
        (r"^7\.[0-4]\b", "High", "OpenSSH 7.0-7.4 has known vulnerabilities; upgrade recommended."),
    ],
    "Apache": [
        (r"^1\.", "Critical", "Apache 1.x is end-of-life and unsupported."),
        (r"^2\.2", "High", "Apache 2.2.x is end-of-life; no security patches are issued."),
        (r"^2\.4\.(4[0-9]|[0-3][0-9])(?!\d)", "Critical", "Apache 2.4.49/2.4.50 are vulnerable to path traversal / RCE (CVE-2021-41773, CVE-2021-42013)."),
    ],
    "nginx": [
        (r"^0\.", "Critical", "nginx 0.x is extremely outdated."),
        (r"^1\.(0|1[0-6])\.", "Medium", "nginx version is old; newer releases contain security fixes."),
    ],
    "vsftpd": [
        (r"^2\.3\.4$", "Critical", "This exact version has a known backdoor (CVE-2011-2523)."),
    ],
    "Microsoft-IIS": [
        (r"^[1-6]\.", "Critical", "IIS 6.0 and earlier are end-of-life and carry numerous known exploits."),
        (r"^7\.", "High", "IIS 7.x is old; confirm patch level."),
    ],
    "ProFTPD": [
        (r"^1\.3\.[0-3][a-z]?\b", "High", "Older ProFTPD releases are affected by several known CVEs."),
    ],
}


def match_local_vulndb(product, version):
    """Return [(severity, description), ...] for a known-outdated version pattern."""
    if not product or not version:
        return []
    findings = []
    patterns = VULN_DB.get(product)
    if not patterns:
        return findings
    for pattern, severity, description in patterns:
        if re.search(pattern, version):
            findings.append((severity, description))
    return findings
