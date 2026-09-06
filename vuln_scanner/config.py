"""Static configuration: port lists, header expectations, severity ordering."""

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
    443, 445, 993, 995, 1433, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443,
]

DEFAULT_TIMEOUT = 2.0

SERVICE_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MS-RPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
}

# Ports considered inherently risky if exposed, regardless of banner.
RISKY_PORTS = {
    23: ("High", "Telnet transmits credentials and data in plaintext. Disable it and use SSH instead."),
    21: ("Low", "FTP is often unencrypted. Confirm whether anonymous login or plaintext auth is enabled."),
    445: ("Medium", "SMB exposed to the network can be a common lateral-movement target; restrict access."),
    3389: ("Medium", "RDP exposed to the internet is a frequent brute-force / exploit target; restrict access or use a VPN."),
    135: ("Low", "MS-RPC endpoint mapper exposure can aid reconnaissance of Windows services."),
    6379: ("High", "Redis exposed without authentication is a common ransomware/wiping target; bind to localhost or require auth."),
    5432: ("Low", "PostgreSQL exposed to the network should be firewalled and require strong authentication."),
}

# Security headers we expect to see on HTTP(S) responses, with a short
# rationale used in report findings.
SECURITY_HEADERS = {
    "Strict-Transport-Security": "Enforces HTTPS and helps prevent protocol-downgrade / SSL-stripping attacks.",
    "X-Frame-Options": "Helps prevent clickjacking by controlling whether the page can be framed.",
    "X-Content-Type-Options": "Prevents MIME-sniffing that can turn some responses into executable content.",
    "Content-Security-Policy": "Restricts the sources scripts/styles/etc. can be loaded from, mitigating XSS.",
    "Referrer-Policy": "Controls how much referrer information is leaked to other sites.",
    "Permissions-Policy": "Restricts which browser features/APIs the page may use.",
}

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

# CVSS v3.x base score -> qualitative severity, per FIRST.org spec.
CVSS_V3_BANDS = [
    (9.0, 10.0, "Critical"),
    (7.0, 8.9, "High"),
    (4.0, 6.9, "Medium"),
    (0.1, 3.9, "Low"),
    (0.0, 0.0, "Info"),
]

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
