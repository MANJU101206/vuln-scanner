# Vulnerability Scanner v2

A Python vulnerability scanner: TCP port scanning, service/version
fingerprinting, live CVE lookups against the NVD with CVSS scores, HTTP
security-header auditing, TLS/certificate analysis, and JSON/HTML/Markdown
reporting.

## Legal / Ethical Notice

**Only scan systems you own or have explicit written permission to test.**
Scanning systems without authorization may be illegal under computer misuse
laws in your jurisdiction (e.g. the CFAA in the US, the Computer Misuse Act
in the UK). This tool includes an interactive authorization confirmation for
that reason — do not bypass it (`--yes`) except in your own lab or test
environment.

## What's new in v2

- **Package layout** (`vuln_scanner/`) instead of a single script, with unit
  tests and CI.
- **Better service/version detection** (`service_detect.py`) — regex
  signatures across SSH, HTTP servers, FTP, SMTP, and common databases, plus
  proper HTTP header parsing (`Server`, `X-Powered-By`) instead of
  substring-matching a raw banner.
- **CVE / NVD integration** (`cve.py`) — live lookups against the
  [NVD CVE 2.0 API](https://nvd.nist.gov/developers/vulnerabilities),
  with on-disk caching and client-side rate limiting. Falls back
  automatically to a small offline database if the network is unavailable
  or `--no-cve` is passed.
- **CVSS scoring** (`cvss.py`) — maps NVD's CVSS v3.1/v3.0/v2 base scores to
  Critical/High/Medium/Low/Info, and surfaces the score + vector in reports.
- **HTTP security-header checks** (`http_checks.py`) — checks real,
  case-insensitively parsed response headers (HSTS, CSP, X-Frame-Options,
  X-Content-Type-Options, Referrer-Policy, Permissions-Policy), flags
  `unsafe-inline` CSPs, and flags version-disclosing `Server`/`X-Powered-By`
  headers.
- **TLS analysis** (`tls_checks.py`) — detects legacy TLS 1.0/1.1 support,
  weak cipher suites (RC4/3DES/NULL), and certificate issues (expired,
  expiring soon, self-signed).
- **JSON / HTML / Markdown reports** (`report.py`) — `--format json|html|markdown`.
- **Unit tests** (`tests/`) — 49 tests covering fingerprinting, CVSS mapping,
  header checks, TLS certificate logic, CVE client caching/fallback (network
  mocked), port parsing, and all three report formats.
- **GitHub Actions CI** (`.github/workflows/ci.yml`) — lint + test matrix
  across Python 3.9–3.12, plus a CLI smoke test.

## Requirements

- Python 3.8+
- No third-party runtime dependencies (standard library only).
- `pytest` and `flake8` for running tests/lint locally (see `requirements.txt`).

## Install

```bash
pip install -e .
```

This installs a `vuln-scanner` console command. You can also run it without
installing via `python -m vuln_scanner`.

## Usage

```bash
vuln-scanner TARGET [options]
# or
python -m vuln_scanner TARGET [options]
```

### Options

| Flag              | Description                                                                 |
|-------------------|------------------------------------------------------------------------------|
| `--ports`         | Ports to scan: a range (`1-1024`), a list (`22,80,443`), or a single port.   |
| `--timeout`       | Socket timeout in seconds (default: `2.0`).                                 |
| `--format`        | Report format: `markdown` (default), `json`, or `html`.                     |
| `--output`        | Report path (default: `vuln_report.<ext>` based on `--format`).             |
| `--active`        | Enables more intrusive checks (currently: anonymous FTP login attempt).     |
| `--yes`           | Skips the interactive authorization confirmation. Lab/automated use only.   |
| `--no-cve`        | Disable live NVD lookups; use only the local offline vulnerability database.|
| `--nvd-api-key`   | NVD API key (raises rate limits). Or set `NVD_API_KEY` env var.             |
| `--max-workers`   | Max concurrent port-scan threads (default: `100`).                          |

### Examples

```bash
# Scan localhost using the default common-ports list, Markdown report
vuln-scanner 127.0.0.1

# Scan a custom port range, write an HTML report
vuln-scanner scanme.example.com --ports 1-1024 --format html --output report.html

# JSON report, active FTP check, skip confirmation (lab use only)
vuln-scanner 192.168.1.10 --active --yes --format json --output report.json

# Fully offline (no NVD calls at all)
vuln-scanner 127.0.0.1 --no-cve
```

### NVD API key

Live CVE lookups work without a key, but NVD rate-limits unauthenticated
callers to 5 requests / 30s. An API key (get one at
https://nvd.nist.gov/developers/request-an-api-key) raises this to 50 / 30s:

```bash
export NVD_API_KEY=your-key-here
vuln-scanner scanme.example.com
```

## Trying it safely

Spin up a local test server, then scan it:

```bash
python3 -m http.server 8080
```

In a second terminal:

```bash
vuln-scanner 127.0.0.1 --ports 8080
```

## Running tests

```bash
pip install -r requirements.txt
pip install -e .
pytest -v
flake8 vuln_scanner tests
```

Tests mock all network calls (NVD API, sockets), so the suite runs fully
offline and deterministically.

## Project layout

```
vuln_scanner/
  config.py          # ports, headers, severity bands
  network.py          # TCP connect + banner grabbing primitives
  service_detect.py   # banner/header -> (product, version) fingerprinting
  local_vulndb.py      # small offline pattern DB (fast, offline signal)
  cve.py               # NVD CVE 2.0 API client, caching, offline fallback
  cvss.py              # CVSS score -> severity mapping
  http_checks.py       # security-header auditing
  tls_checks.py        # TLS version / cipher / certificate analysis
  active_checks.py     # intrusive checks, gated by --active
  scan_engine.py       # orchestration
  report.py            # JSON / HTML / Markdown report generation
  cli.py               # argparse CLI
tests/                 # unit tests (network mocked)
.github/workflows/ci.yml
```

## Sample report structure

1. **Summary** — counts by severity (Critical / High / Medium / Low / Info).
2. **Open Ports** — port, service, detected product/version, banner.
3. **Detailed Findings** — every issue found, with severity and description.
4. **CVE Details** (when applicable) — CVE ID, CVSS score/version, description, NVD link.
5. **Recommendations** — remediation guidance.

## Limitations

This is an educational tool, not a production security scanner:

- CVE data depends on NVD's keyword search matching your detected
  product/version string; it is not guaranteed to be exhaustive, and the
  offline fallback database is small and illustrative.
- It does not perform exploitation, only detection based on banners,
  headers, and TLS/certificate signals.
- Some services don't return a banner, or return one the fingerprinter
  doesn't recognize, resulting in false negatives.
- It should be paired with, not substituted for, a full professional
  penetration test.

## License

Feel free to use, modify, and share for educational purposes. See `LICENSE`.
