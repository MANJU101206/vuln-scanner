"""Low-level network primitives: TCP connect scanning and banner grabbing."""

import socket
import ssl

from .config import DEFAULT_TIMEOUT


def scan_port(host, port, timeout=DEFAULT_TIMEOUT):
    """Return True if the port accepts a TCP connection."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            return result == 0
    except socket.error:
        return False


def grab_tcp_banner(host, port, timeout=DEFAULT_TIMEOUT, probe=None):
    """Read a banner from a plain TCP service, optionally sending a probe first."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, port))
            if probe:
                sock.sendall(probe)
            data = sock.recv(4096)
            return data.decode(errors="ignore")
    except (socket.error, ssl.SSLError, OSError):
        return ""


def grab_http_banner(host, port, timeout=DEFAULT_TIMEOUT, use_tls=False):
    """Perform a minimal HTTP HEAD request and return the raw response text."""
    request = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: vuln-scanner/2.0\r\n\r\n".encode()
    try:
        raw_sock = socket.create_connection((host, port), timeout=timeout)
        try:
            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(raw_sock, server_hostname=host)
            else:
                sock = raw_sock
            sock.settimeout(timeout)
            sock.sendall(request)
            chunks = []
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    if sum(len(c) for c in chunks) > 32768:
                        break
            except socket.timeout:
                pass
            data = b"".join(chunks).decode(errors="ignore")
            tls_version = sock.version() if use_tls else None
            return data, tls_version
        finally:
            try:
                sock.close()
            except Exception:
                pass
    except (socket.error, ssl.SSLError, OSError):
        return "", None


def parse_http_headers(raw_response):
    """Parse a raw HTTP response into (status_line, headers dict, body)."""
    if not raw_response:
        return "", {}, ""
    parts = raw_response.split("\r\n\r\n", 1)
    head = parts[0]
    body = parts[1] if len(parts) > 1 else ""
    lines = head.split("\r\n")
    status_line = lines[0] if lines else ""
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            key, _, value = line.partition(":")
            headers[key.strip()] = value.strip()
    return status_line, headers, body
