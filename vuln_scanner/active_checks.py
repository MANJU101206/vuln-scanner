"""Optional, more intrusive checks -- only run with --active."""

import socket

from .config import DEFAULT_TIMEOUT


def check_ftp_anonymous(host, port, timeout=DEFAULT_TIMEOUT):
    """Attempt an anonymous FTP login. Only meant to run with --active."""
    findings = []
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, port))
            sock.recv(512)
            sock.sendall(b"USER anonymous\r\n")
            sock.recv(512)
            sock.sendall(b"PASS anonymous@example.com\r\n")
            resp2 = sock.recv(512).decode(errors="ignore")
            if "230" in resp2:
                findings.append(("High", "Anonymous FTP login is permitted -- disable anonymous access unless required."))
    except Exception:
        pass
    return findings
