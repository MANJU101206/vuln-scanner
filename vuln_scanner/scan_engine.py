"""Orchestrates port scanning, fingerprinting, and all check modules."""

import concurrent.futures

from .active_checks import check_ftp_anonymous
from .config import COMMON_PORTS, DEFAULT_TIMEOUT, RISKY_PORTS, SERVICE_NAMES
from .cve import CveClient
from .http_checks import check_security_headers, fetch_http_response
from .local_vulndb import match_local_vulndb
from .network import grab_tcp_banner, scan_port
from .service_detect import identify_service
from .tls_checks import analyze_tls

HTTP_PORTS = {80, 8080}
HTTPS_PORTS = {443, 8443}


def parse_port_range(port_arg):
    if port_arg is None:
        return list(COMMON_PORTS)
    if "-" in port_arg:
        start, end = port_arg.split("-")
        return list(range(int(start), int(end) + 1))
    if "," in port_arg:
        return [int(p) for p in port_arg.split(",")]
    return [int(port_arg)]


def service_name_for_port(port):
    return SERVICE_NAMES.get(port, "Unknown")


def _grab_banner_for_port(host, port, timeout):
    """Grab a banner appropriate to the port; returns (banner, headers, tls_version)."""
    headers = {}
    tls_version = None
    if port in HTTP_PORTS:
        status_line, headers, _ = fetch_http_response(host, port, timeout, use_tls=False)
        banner = status_line
    elif port in HTTPS_PORTS:
        status_line, headers, tls_version = fetch_http_response(host, port, timeout, use_tls=True)
        banner = status_line
    else:
        banner = grab_tcp_banner(host, port, timeout)
    return banner, headers, tls_version


def scan_single_port(host, port, timeout, active_checks, cve_client):
    """Run all applicable checks for one open port and return a result dict."""
    service = service_name_for_port(port)
    banner, headers, tls_version = _grab_banner_for_port(host, port, timeout)

    findings = []
    cves = []

    if port in RISKY_PORTS:
        findings.append(RISKY_PORTS[port])

    fingerprint = identify_service(banner, header_hints=headers)
    if fingerprint.product:
        findings.extend(match_local_vulndb(fingerprint.product, fingerprint.version or ""))
        if cve_client is not None:
            cves = cve_client.lookup(fingerprint.product, fingerprint.version)
            for cve in cves:
                findings.append((cve["severity"], f"{cve['id']}: {cve['description'][:200]}"))

    tls_details = None
    if port in HTTP_PORTS or port in HTTPS_PORTS:
        findings.extend(check_security_headers(headers))
    if port in HTTPS_PORTS:
        tls_findings, tls_details = analyze_tls(host, port, timeout)
        findings.extend(tls_findings)

    if active_checks and port == 21:
        findings.extend(check_ftp_anonymous(host, port, timeout))

    if not findings:
        findings.append(("Info", "Port is open; no specific issues identified by this scanner."))

    return {
        "port": port,
        "service": service,
        "product": fingerprint.product,
        "version": fingerprint.version,
        "banner": banner.split("\n")[0].strip() if banner else "(no banner)",
        "headers": headers,
        "tls": tls_details,
        "cves": cves,
        "findings": findings,
    }


def scan_host(host, ports, timeout=DEFAULT_TIMEOUT, active_checks=False,
              max_workers=100, use_cve_lookup=True, nvd_api_key=None,
              offline_cve=False):
    """Scan `host` across `ports`, returning a list of per-port result dicts."""
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {executor.submit(scan_port, host, port, timeout): port for port in ports}
        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            try:
                if future.result():
                    open_ports.append(port)
            except Exception:
                continue
    open_ports.sort()

    cve_client = CveClient(api_key=nvd_api_key, offline=offline_cve) if use_cve_lookup else None

    results = []
    for port in open_ports:
        results.append(scan_single_port(host, port, timeout, active_checks, cve_client))
    return results
