"""
Service / version fingerprinting.

Turns a raw banner (or HTTP `Server`/`X-Powered-By` header) into a
structured (product, version) pair that downstream modules (CVE lookup,
local vuln DB matching) can use, instead of doing ad-hoc substring
matching on the raw banner text.
"""

import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class ServiceFingerprint:
    product: Optional[str] = None
    version: Optional[str] = None
    extra: Optional[str] = None  # e.g. OS hint, module info
    raw_banner: str = ""

    @property
    def display_name(self):
        if self.product and self.version:
            return f"{self.product} {self.version}"
        if self.product:
            return self.product
        return "unknown"


# Each entry: (compiled regex, product name, version group index)
# Regexes are intentionally permissive about surrounding text since banners
# vary a lot between vendors/configurations.
_SIGNATURES = [
    (re.compile(r"SSH-[\d.]+-OpenSSH[_-]([\w.]+)", re.I), "OpenSSH"),
    (re.compile(r"SSH-[\d.]+-(?:dropbear)[_-]?([\w.]*)", re.I), "Dropbear SSH"),
    (re.compile(r"Server:\s*Apache/([\d.]+)", re.I), "Apache"),
    (re.compile(r"Server:\s*nginx/([\d.]+)", re.I), "nginx"),
    (re.compile(r"Server:\s*Microsoft-IIS/([\d.]+)", re.I), "Microsoft-IIS"),
    (re.compile(r"Server:\s*lighttpd/([\d.]+)", re.I), "lighttpd"),
    (re.compile(r"Server:\s*cherokee[/ ]?([\d.]*)", re.I), "Cherokee"),
    (re.compile(r"Server:\s*gunicorn/([\d.]+)", re.I), "gunicorn"),
    (re.compile(r"X-Powered-By:\s*PHP/([\d.]+)", re.I), "PHP"),
    (re.compile(r"X-Powered-By:\s*Express", re.I), "Express"),
    (re.compile(r"220[ -].*vsftpd\s+([\d.]+)", re.I), "vsftpd"),
    (re.compile(r"220[ -].*ProFTPD\s+([\w.]+)", re.I), "ProFTPD"),
    (re.compile(r"220[ -].*Pure-?FTPd", re.I), "Pure-FTPd"),
    (re.compile(r"220[ -].*FileZilla Server\s*([\w.]*)", re.I), "FileZilla Server"),
    (re.compile(r"220[ -].*Microsoft FTP Service", re.I), "Microsoft FTP Service"),
    (re.compile(r"\+OK.*Dovecot", re.I), "Dovecot"),
    (re.compile(r"220[ -].*ESMTP\s+Postfix", re.I), "Postfix"),
    (re.compile(r"220[ -].*ESMTP\s+Exim\s+([\d.]+)", re.I), "Exim"),
    (re.compile(r"220[ -].*Microsoft ESMTP MAIL Service", re.I), "Microsoft Exchange"),
    (re.compile(r"^([\d.]+)-MariaDB", re.I | re.M), "MariaDB"),
    (re.compile(r"mysql_native_password|^[\d.]+-log", re.I | re.M), "MySQL"),
    (re.compile(r"REDIS", re.I), "Redis"),
    (re.compile(r"PostgreSQL", re.I), "PostgreSQL"),
]

_BARE_VERSION = re.compile(r"([\d]+\.[\d]+(?:\.[\d]+)?[a-zA-Z0-9\-]*)")


def identify_service(banner, header_hints=None):
    """
    Identify product/version from a raw banner string and, for HTTP(S)
    services, a dict of parsed response headers (preferred over guessing
    from a truncated raw banner).
    """
    header_hints = header_hints or {}
    search_text = banner or ""

    # Prefer explicit HTTP headers when available -- far more reliable
    # than regexing the raw response body/status line.
    server_header = header_hints.get("Server", "")
    powered_by = header_hints.get("X-Powered-By", "")
    if server_header:
        search_text = f"Server: {server_header}\n" + search_text
    if powered_by:
        search_text = f"X-Powered-By: {powered_by}\n" + search_text

    for pattern, product in _SIGNATURES:
        match = pattern.search(search_text)
        if match:
            version = None
            if match.groups():
                candidate = match.group(1)
                if candidate:
                    version = candidate
            return ServiceFingerprint(product=product, version=version, raw_banner=banner)

    return ServiceFingerprint(product=None, version=None, raw_banner=banner)


def guess_os_hint(banner):
    """Very rough OS hint extraction from banners that advertise it (e.g. Apache)."""
    if not banner:
        return None
    m = re.search(r"\((Ubuntu|Debian|CentOS|Red Hat|Win32|Win64|Unix|FreeBSD)\)", banner, re.I)
    return m.group(1) if m else None
