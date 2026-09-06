"""HTTP(S) response analysis: security headers and basic fingerprinting."""

from .config import DEFAULT_TIMEOUT, SECURITY_HEADERS
from .network import grab_http_banner, parse_http_headers


def fetch_http_response(host, port, timeout=DEFAULT_TIMEOUT, use_tls=False):
    """Fetch and parse an HTTP(S) response. Returns (status_line, headers, tls_version)."""
    raw, tls_version = grab_http_banner(host, port, timeout=timeout, use_tls=use_tls)
    status_line, headers, _body = parse_http_headers(raw)
    return status_line, headers, tls_version


def check_security_headers(headers):
    """
    Check a parsed headers dict (case-sensitive keys as returned by the
    server) against the expected security-header set, case-insensitively.

    Returns a list of (severity, description) findings.
    """
    findings = []
    if not headers:
        return findings

    lower_keys = {k.lower() for k in headers}
    missing = [h for h in SECURITY_HEADERS if h.lower() not in lower_keys]

    for header in missing:
        rationale = SECURITY_HEADERS[header]
        severity = "Medium" if header in ("Strict-Transport-Security", "Content-Security-Policy") else "Low"
        findings.append((severity, f"Missing '{header}' header. {rationale}"))

    # Flag overly permissive/legacy configurations if present.
    csp = next((v for k, v in headers.items() if k.lower() == "content-security-policy"), None)
    if csp and "unsafe-inline" in csp.lower():
        findings.append(("Low", "Content-Security-Policy allows 'unsafe-inline', which weakens XSS protection."))

    server_header = next((v for k, v in headers.items() if k.lower() == "server"), None)
    if server_header and any(ch.isdigit() for ch in server_header):
        findings.append(("Info", f"Server header discloses version information ('{server_header}'), aiding reconnaissance."))

    xpb = next((v for k, v in headers.items() if k.lower() == "x-powered-by"), None)
    if xpb:
        findings.append(("Info", f"'X-Powered-By: {xpb}' header discloses backend technology; consider removing it."))

    return findings
