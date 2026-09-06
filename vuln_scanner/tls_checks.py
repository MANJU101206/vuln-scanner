"""TLS protocol-version, cipher, and certificate analysis."""

import socket
import ssl
from datetime import datetime, timezone

from .config import DEFAULT_TIMEOUT

# Protocols we specifically probe for, oldest-to-newest, with the
# ssl.TLSVersion bounds used to force negotiation to exactly that version.
_LEGACY_PROTOCOLS = [
    ("SSLv3", None, None),  # handled separately; usually unsupported by the stdlib build
    ("TLS 1.0", "TLSv1", "TLSv1"),
    ("TLS 1.1", "TLSv1_1", "TLSv1_1"),
]


def _try_negotiate(host, port, timeout, min_attr, max_attr):
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = getattr(ssl.TLSVersion, min_attr)
        ctx.maximum_version = getattr(ssl.TLSVersion, max_attr)
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except Exception:
        return False


def check_legacy_protocols(host, port, timeout=DEFAULT_TIMEOUT):
    """Return findings for any outdated TLS protocol versions still accepted."""
    findings = []
    for label, min_attr, max_attr in _LEGACY_PROTOCOLS:
        if min_attr is None:
            continue
        if _try_negotiate(host, port, timeout, min_attr, max_attr):
            severity = "High" if label == "TLS 1.0" else "Medium"
            findings.append((severity, f"Server accepts outdated {label}, which has known weaknesses and should be disabled."))
    return findings


def get_negotiated_protocol(host, port, timeout=DEFAULT_TIMEOUT):
    """Return the TLS version negotiated using default (modern) client settings."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return ssock.version(), ssock.cipher()
    except Exception:
        return None, None


def get_certificate_info(host, port, timeout=DEFAULT_TIMEOUT):
    """
    Fetch and summarize the server's certificate: subject, issuer,
    expiry, and whether it appears self-signed.

    Returns a dict, or None if the certificate couldn't be retrieved.
    """
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
                cert = ssock.getpeercert()
    except Exception:
        return None

    info = {"self_signed": None, "not_after": None, "days_until_expiry": None,
            "subject": None, "issuer": None}

    if cert:
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        info["subject"] = subject.get("commonName")
        info["issuer"] = issuer.get("commonName")
        info["self_signed"] = subject.get("commonName") == issuer.get("commonName")
        not_after = cert.get("notAfter")
        if not_after:
            try:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                info["not_after"] = expiry.isoformat()
                info["days_until_expiry"] = (expiry - datetime.now(timezone.utc)).days
            except ValueError:
                pass
    elif der:
        # No parsed dict available (verify_mode CERT_NONE with some OpenSSL
        # builds); we still know a cert was presented.
        info["subject"] = "(unparsed certificate)"

    return info


def check_certificate(host, port, timeout=DEFAULT_TIMEOUT):
    """Return findings related to certificate validity/expiry/self-signing."""
    findings = []
    info = get_certificate_info(host, port, timeout)
    if info is None:
        return findings

    if info.get("self_signed"):
        findings.append(("Medium", "Server presents a self-signed certificate; clients will see trust warnings."))

    days = info.get("days_until_expiry")
    if days is not None:
        if days < 0:
            findings.append(("Critical", f"TLS certificate expired {-days} day(s) ago."))
        elif days < 14:
            findings.append(("High", f"TLS certificate expires in {days} day(s); renew soon."))
        elif days < 30:
            findings.append(("Medium", f"TLS certificate expires in {days} day(s)."))

    return findings


def analyze_tls(host, port, timeout=DEFAULT_TIMEOUT):
    """Run the full TLS analysis suite and return (findings, details_dict)."""
    findings = []
    findings.extend(check_legacy_protocols(host, port, timeout))
    findings.extend(check_certificate(host, port, timeout))

    protocol, cipher = get_negotiated_protocol(host, port, timeout)
    if cipher and cipher[0] and ("RC4" in cipher[0] or "3DES" in cipher[0] or "NULL" in cipher[0]):
        findings.append(("High", f"Server negotiated a weak cipher suite ({cipher[0]})."))

    cert_info = get_certificate_info(host, port, timeout) or {}
    details = {
        "negotiated_protocol": protocol,
        "negotiated_cipher": cipher[0] if cipher else None,
        "certificate_subject": cert_info.get("subject"),
        "certificate_issuer": cert_info.get("issuer"),
        "certificate_expires": cert_info.get("not_after"),
        "days_until_expiry": cert_info.get("days_until_expiry"),
        "self_signed": cert_info.get("self_signed"),
    }
    return findings, details
