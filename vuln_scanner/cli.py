#!/usr/bin/env python3
"""
Vulnerability Scanner CLI
-------------------------

IMPORTANT / LEGAL NOTICE
Only scan systems you own or have explicit written permission to test.
Scanning systems without authorization may be illegal in your jurisdiction
(e.g. the CFAA in the US, the Computer Misuse Act in the UK). This tool
includes a confirmation prompt for that reason -- do not bypass it (--yes)
except in your own lab or test environment.

Usage:
    python -m vuln_scanner TARGET [options]

Examples:
    python -m vuln_scanner 127.0.0.1
    python -m vuln_scanner scanme.example.com --ports 1-1024 --format html --output report.html
    python -m vuln_scanner 192.168.1.10 --active --yes --format json --output report.json
"""

import argparse
import socket
import sys

from . import __version__
from .config import DEFAULT_TIMEOUT
from .report import generate_report
from .scan_engine import parse_port_range, scan_host


def build_parser():
    description = (
        "Educational vulnerability scanner: port scan, service/version fingerprinting, "
        "CVE/CVSS lookups, HTTP security-header checks, and TLS analysis."
    )
    parser = argparse.ArgumentParser(prog="vuln-scanner", description=description)
    parser.add_argument(
        "target", help="Hostname or IP address to scan"
    )
    parser.add_argument(
        "--ports",
        help="Port(s) to scan: e.g. '1-1024', '22,80,443', or a single port. Defaults to a common-ports list.",
    )
    parser.add_argument(
        "--timeout", type=float, default=DEFAULT_TIMEOUT,
        help=f"Socket timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--output", default=None,
        help="Path to write the report (default: vuln_report.<ext> based on --format)",
    )
    parser.add_argument(
        "--format", choices=["markdown", "json", "html"], default="markdown",
        help="Report format (default: markdown)",
    )
    parser.add_argument(
        "--active", action="store_true",
        help="Enable more intrusive checks (e.g. anonymous FTP login attempt)",
    )
    parser.add_argument(
        "--yes", action="store_true",
        help="Skip the interactive authorization confirmation (use only in automated/lab contexts)",
    )
    parser.add_argument(
        "--no-cve", action="store_true",
        help="Disable live NVD lookups; use only the local offline vulnerability database",
    )
    parser.add_argument(
        "--nvd-api-key", default=None,
        help="NVD API key (raises rate limits). Can also be set via NVD_API_KEY env var.",
    )
    parser.add_argument(
        "--max-workers", type=int, default=100,
        help="Max concurrent port-scan threads (default: 100)",
    )
    parser.add_argument("--version", action="version", version=f"vuln-scanner {__version__}")
    return parser


def confirm_authorization(target, skip):
    if skip:
        return True
    confirm = input(f"Confirm you are authorized to scan '{target}' (yes/no): ").strip().lower()
    return confirm in ("yes", "y")


def default_output_path(fmt):
    ext = {"markdown": "md", "json": "json", "html": "html"}[fmt]
    return f"vuln_report.{ext}"


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    print(__doc__)

    if not confirm_authorization(args.target, args.yes):
        print("Authorization not confirmed. Exiting.")
        return 1

    try:
        host_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"Could not resolve host: {args.target}")
        return 1

    ports = parse_port_range(args.ports)
    output_path = args.output or default_output_path(args.format)

    print(f"\nScanning {args.target} ({host_ip}) across {len(ports)} port(s)...\n")

    results = scan_host(
        args.target,
        ports,
        timeout=args.timeout,
        active_checks=args.active,
        max_workers=args.max_workers,
        use_cve_lookup=True,
        nvd_api_key=args.nvd_api_key,
        offline_cve=args.no_cve,
    )

    if not results:
        print("No open ports found among the scanned range.")
    else:
        print(f"Found {len(results)} open port(s):")
        for r in results:
            product = f" [{r['product']} {r['version']}]" if r.get("product") else ""
            print(f"  - Port {r['port']} ({r['service']}){product}: {r['banner']}")

    _report_text, counts = generate_report(args.target, results, output_path, fmt=args.format)

    print(f"\nReport written to: {output_path}")
    print(f"Summary: {counts}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
