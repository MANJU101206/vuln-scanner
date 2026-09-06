"""Report generation in JSON, HTML, and Markdown formats."""

import html
import json
from datetime import datetime

from .config import SEVERITY_ORDER

SEVERITY_COLORS = {
    "Critical": "#7f1d1d",
    "High": "#b91c1c",
    "Medium": "#b45309",
    "Low": "#1d4ed8",
    "Info": "#4b5563",
}


def _flatten_findings(results):
    all_findings = []
    for r in results:
        for severity, desc in r["findings"]:
            all_findings.append({
                "severity": severity,
                "port": r["port"],
                "service": r["service"],
                "description": desc,
            })
    all_findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))
    return all_findings


def _severity_counts(all_findings):
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in all_findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return counts


def build_report_data(host, results):
    """Build a format-agnostic report data structure from raw scan results."""
    all_findings = _flatten_findings(results)
    counts = _severity_counts(all_findings)
    return {
        "target": host,
        "scan_date": datetime.now().isoformat(timespec="seconds"),
        "open_port_count": len(results),
        "severity_summary": counts,
        "open_ports": [
            {
                "port": r["port"],
                "service": r["service"],
                "product": r.get("product"),
                "version": r.get("version"),
                "banner": r["banner"],
                "tls": r.get("tls"),
                "cves": r.get("cves", []),
            }
            for r in results
        ],
        "findings": all_findings,
    }


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------

def generate_json_report(host, results, output_path):
    data = build_report_data(host, results)
    text = json.dumps(data, indent=2, default=str)
    with open(output_path, "w") as f:
        f.write(text)
    return text, data["severity_summary"]


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------

def generate_markdown_report(host, results, output_path):
    data = build_report_data(host, results)
    counts = data["severity_summary"]

    lines = []
    lines.append("# Vulnerability Scan Report\n")
    lines.append(f"**Target:** {host}  ")
    lines.append(f"**Scan date:** {data['scan_date']}  ")
    lines.append(f"**Open ports found:** {data['open_port_count']}\n")

    lines.append("## Summary\n")
    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        lines.append(f"| {sev} | {counts[sev]} |")
    lines.append("")

    lines.append("## Open Ports\n")
    lines.append("| Port | Service | Product/Version | Banner |")
    lines.append("|---|---|---|---|")
    for p in data["open_ports"]:
        product = f"{p['product']} {p['version']}".strip() if p["product"] else "-"
        banner_display = p["banner"].replace("|", "/")[:80]
        lines.append(f"| {p['port']} | {p['service']} | {product} | {banner_display} |")
    lines.append("")

    lines.append("## Detailed Findings\n")
    if not data["findings"]:
        lines.append("No findings to report.\n")
    else:
        lines.append("| Severity | Port | Service | Finding |")
        lines.append("|---|---|---|---|")
        for f in data["findings"]:
            lines.append(f"| {f['severity']} | {f['port']} | {f['service']} | {f['description']} |")
        lines.append("")

    cve_ports = [p for p in data["open_ports"] if p["cves"]]
    if cve_ports:
        lines.append("## CVE Details\n")
        for p in cve_ports:
            lines.append(f"**Port {p['port']} ({p['product']} {p['version'] or ''})**\n")
            lines.append("| CVE | CVSS | Description |")
            lines.append("|---|---|---|")
            for cve in p["cves"]:
                score = cve.get("cvss_score")
                score_display = f"{score} (v{cve.get('cvss_version')})" if score is not None else "n/a"
                lines.append(f"| [{cve['id']}]({cve.get('url', '')}) | {score_display} | {cve['description'][:150]} |")
            lines.append("")

    lines.append("## Recommendations\n")
    lines.append("- Patch or upgrade any software flagged as outdated above.")
    lines.append("- Close or firewall any open ports that are not required for the service to function.")
    lines.append("- Disable plaintext protocols (e.g. Telnet, unencrypted FTP) in favor of encrypted alternatives (SSH, FTPS/SFTP).")
    lines.append("- Add missing HTTP security headers on any exposed web services.")
    lines.append("- Disable outdated TLS versions (1.0 / 1.1) and weak cipher suites in favor of TLS 1.2+.")
    lines.append("- Renew certificates before expiry and avoid self-signed certificates in production.")
    lines.append("- Re-scan after remediation to confirm issues are resolved.\n")
    lines.append("---")
    footer_note = (
        "*This report was generated by an educational scanning tool. CVE data comes from NVD when reachable, "
        "falling back to a small illustrative offline database otherwise. It is not a substitute for a full "
        "professional penetration test.*"
    )
    lines.append(footer_note)

    report_text = "\n".join(lines)
    with open(output_path, "w") as f:
        f.write(report_text)
    return report_text, counts


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Vulnerability Scan Report - {target}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem auto; max-width: 960px; color: #1f2937; line-height: 1.5; }}
  h1, h2 {{ border-bottom: 1px solid #e5e7eb; padding-bottom: 0.3rem; }}
  table {{ border-collapse: collapse; width: 100%; margin-bottom: 1.5rem; }}
  th, td {{ border: 1px solid #e5e7eb; padding: 0.5rem 0.75rem; text-align: left; font-size: 0.9rem; }}
  th {{ background: #f9fafb; }}
  .badge {{ display: inline-block; padding: 0.15rem 0.55rem; border-radius: 999px; color: white; font-size: 0.75rem; font-weight: 600; }}
  .meta {{ color: #6b7280; margin-bottom: 1.5rem; }}
  footer {{ color: #6b7280; font-size: 0.8rem; margin-top: 2rem; border-top: 1px solid #e5e7eb; padding-top: 1rem; }}
  .summary-cards {{ display: flex; gap: 0.75rem; margin-bottom: 1.5rem; flex-wrap: wrap; }}
  .card {{ border-radius: 8px; padding: 0.75rem 1rem; color: white; min-width: 90px; text-align: center; }}
  .card .count {{ font-size: 1.5rem; font-weight: 700; display: block; }}
</style>
</head>
<body>
<h1>Vulnerability Scan Report</h1>
<p class="meta"><strong>Target:</strong> {target} &nbsp;|&nbsp; <strong>Scan date:</strong> {scan_date} &nbsp;|&nbsp; <strong>Open ports:</strong> {open_port_count}</p>

<div class="summary-cards">
{summary_cards}
</div>

<h2>Open Ports</h2>
<table>
<tr><th>Port</th><th>Service</th><th>Product/Version</th><th>Banner</th></tr>
{open_ports_rows}
</table>

<h2>Detailed Findings</h2>
<table>
<tr><th>Severity</th><th>Port</th><th>Service</th><th>Finding</th></tr>
{findings_rows}
</table>

{cve_section}

<h2>Recommendations</h2>
<ul>
<li>Patch or upgrade any software flagged as outdated above.</li>
<li>Close or firewall any open ports that are not required for the service to function.</li>
<li>Disable plaintext protocols (e.g. Telnet, unencrypted FTP) in favor of encrypted alternatives (SSH, FTPS/SFTP).</li>
<li>Add missing HTTP security headers on any exposed web services.</li>
<li>Disable outdated TLS versions and weak cipher suites in favor of TLS 1.2+.</li>
<li>Renew certificates before expiry and avoid self-signed certificates in production.</li>
<li>Re-scan after remediation to confirm issues are resolved.</li>
</ul>

<footer>
This report was generated by an educational scanning tool. CVE data comes from NVD when reachable, falling back to a
small illustrative offline database otherwise. It is not a substitute for a full professional penetration test.
</footer>
</body>
</html>
"""


def _badge(severity):
    color = SEVERITY_COLORS.get(severity, "#4b5563")
    return f'<span class="badge" style="background:{color}">{html.escape(severity)}</span>'


def generate_html_report(host, results, output_path):
    data = build_report_data(host, results)
    counts = data["severity_summary"]

    summary_cards = "\n".join(
        f'<div class="card" style="background:{SEVERITY_COLORS[sev]}">'
        f'<span class="count">{counts[sev]}</span>{sev}</div>'
        for sev in ["Critical", "High", "Medium", "Low", "Info"]
    )

    open_ports_rows = "\n".join(
        "<tr><td>{port}</td><td>{service}</td><td>{product}</td><td>{banner}</td></tr>".format(
            port=p["port"],
            service=html.escape(p["service"]),
            product=html.escape(f"{p['product']} {p['version']}".strip()) if p["product"] else "-",
            banner=html.escape(p["banner"])[:120],
        )
        for p in data["open_ports"]
    ) or "<tr><td colspan=4>No open ports found.</td></tr>"

    findings_rows = "\n".join(
        "<tr><td>{sev}</td><td>{port}</td><td>{service}</td><td>{desc}</td></tr>".format(
            sev=_badge(f["severity"]),
            port=f["port"],
            service=html.escape(f["service"]),
            desc=html.escape(f["description"]),
        )
        for f in data["findings"]
    ) or "<tr><td colspan=4>No findings to report.</td></tr>"

    cve_ports = [p for p in data["open_ports"] if p["cves"]]
    cve_section = ""
    if cve_ports:
        blocks = []
        for p in cve_ports:
            rows = "\n".join(
                '<tr><td><a href="{url}">{id}</a></td><td>{score}</td><td>{desc}</td></tr>'.format(
                    url=html.escape(cve.get("url") or "#"),
                    id=html.escape(cve["id"] or ""),
                    score=f"{cve['cvss_score']} (v{cve['cvss_version']})" if cve.get("cvss_score") is not None else "n/a",
                    desc=html.escape(cve["description"])[:200],
                )
                for cve in p["cves"]
            )
            blocks.append(
                f"<h3>Port {p['port']} ({html.escape(str(p['product']))} {html.escape(str(p['version'] or ''))})</h3>"
                f"<table><tr><th>CVE</th><th>CVSS</th><th>Description</th></tr>{rows}</table>"
            )
        cve_section = "<h2>CVE Details</h2>" + "\n".join(blocks)

    html_text = _HTML_TEMPLATE.format(
        target=html.escape(host),
        scan_date=html.escape(data["scan_date"]),
        open_port_count=data["open_port_count"],
        summary_cards=summary_cards,
        open_ports_rows=open_ports_rows,
        findings_rows=findings_rows,
        cve_section=cve_section,
    )

    with open(output_path, "w") as f:
        f.write(html_text)
    return html_text, counts


FORMAT_GENERATORS = {
    "json": generate_json_report,
    "html": generate_html_report,
    "markdown": generate_markdown_report,
}


def generate_report(host, results, output_path, fmt="markdown"):
    generator = FORMAT_GENERATORS.get(fmt)
    if generator is None:
        raise ValueError(f"Unknown report format: {fmt}")
    return generator(host, results, output_path)
