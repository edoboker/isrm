"""TLS/certificate evidence collector."""

from __future__ import annotations

import logging
import socket
import ssl
from datetime import datetime, timezone

from cryptography import x509

from isrm.models import CollectorResult, CollectorStatus, TLSEvidence

logger = logging.getLogger(__name__)

_COLLECTOR_NAME = "tls"
_PORT = 443
_TIMEOUT = 10


def collect_tls(hostname: str) -> CollectorResult:
    """Collect TLS and certificate evidence for a hostname.

    Args:
        hostname: The hostname to inspect (port 443).

    Returns:
        A CollectorResult containing TLSEvidence or a failure status.
    """
    try:
        return _do_collect(hostname)
    except Exception as exc:
        logger.warning("TLS collector failed for %s: %s", hostname, exc)
        return CollectorResult(
            name=_COLLECTOR_NAME,
            status=CollectorStatus.FAILED,
            summary=f"TLS connection failed: {exc}",
            payload=TLSEvidence(connected=False, failure_reason=str(exc)),
            errors=[str(exc)],
        )


def _do_collect(hostname: str) -> CollectorResult:
    ctx = ssl.create_default_context()

    raw_cert_der: bytes | None = None
    tls_version: str | None = None

    with socket.create_connection((hostname, _PORT), timeout=_TIMEOUT) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            tls_version = ssock.version()
            raw_cert_der = ssock.getpeercert(binary_form=True)

    if not raw_cert_der:
        return CollectorResult(
            name=_COLLECTOR_NAME,
            status=CollectorStatus.PARTIAL,
            summary="TLS connected but no certificate returned.",
            payload=TLSEvidence(connected=True, tls_version=tls_version),
        )

    cert = x509.load_der_x509_certificate(raw_cert_der)

    subject = cert.subject.rfc4514_string()
    issuer = cert.issuer.rfc4514_string()
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    now = datetime.now(timezone.utc)
    expired = now > not_after

    # Hostname match: check SAN first, then CN
    hostname_match = _check_hostname_match(cert, hostname)

    # Chain trust: if ssl.create_default_context() connected without error, it's trusted
    chain_trusted = True

    evidence = TLSEvidence(
        connected=True,
        subject=subject,
        issuer=issuer,
        not_before=not_before,
        not_after=not_after,
        expired=expired,
        hostname_match=hostname_match,
        chain_trusted=chain_trusted,
        tls_version=tls_version,
    )

    if expired:
        status = CollectorStatus.PARTIAL
        summary = f"TLS certificate is expired (expired {not_after.date()})."
    elif not hostname_match:
        status = CollectorStatus.PARTIAL
        summary = f"TLS certificate does not match hostname {hostname!r}."
    else:
        status = CollectorStatus.OK
        days_left = (not_after - now).days
        summary = (
            f"TLS certificate valid, trusted, matches hostname. "
            f"Expires in {days_left} days ({not_after.date()})."
        )

    return CollectorResult(
        name=_COLLECTOR_NAME,
        status=status,
        summary=summary,
        payload=evidence,
    )


def _check_hostname_match(cert: x509.Certificate, hostname: str) -> bool:
    """Check whether a certificate covers the given hostname."""
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = san_ext.value.get_values_for_type(x509.DNSName)
        for name in dns_names:
            if _dns_name_matches(name, hostname):
                return True
        return False
    except x509.ExtensionNotFound:
        pass

    # Fall back to CN
    try:
        cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        return _dns_name_matches(str(cn), hostname)
    except (IndexError, Exception):
        return False


def _dns_name_matches(pattern: str, hostname: str) -> bool:
    """Match a certificate DNS name pattern (supports leading wildcard) against a hostname."""
    if pattern.startswith("*."):
        suffix = pattern[2:]
        parts = hostname.split(".", 1)
        return len(parts) == 2 and parts[1] == suffix
    return pattern == hostname
