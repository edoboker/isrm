"""HTTP evidence collector."""

from __future__ import annotations

import logging

import httpx

from isrm.models import CollectorResult, CollectorStatus, HTTPEvidence

logger = logging.getLogger(__name__)

_COLLECTOR_NAME = "http"
_TIMEOUT = 15
_SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
]


def collect_http(url: str) -> CollectorResult:
    """Collect HTTP posture evidence for a URL.

    Args:
        url: The target URL to request.

    Returns:
        A CollectorResult containing HTTPEvidence or a failure status.
    """
    try:
        return _do_collect(url)
    except httpx.TimeoutException as exc:
        logger.warning("HTTP collector timed out for %s: %s", url, exc)
        return CollectorResult(
            name=_COLLECTOR_NAME,
            status=CollectorStatus.FAILED,
            summary="HTTP request timed out.",
            errors=[str(exc)],
        )
    except Exception as exc:
        logger.warning("HTTP collector failed for %s: %s", url, exc)
        return CollectorResult(
            name=_COLLECTOR_NAME,
            status=CollectorStatus.FAILED,
            summary=f"HTTP request failed: {exc}",
            errors=[str(exc)],
        )


def _do_collect(url: str) -> CollectorResult:
    redirect_chain: list[str] = []

    with httpx.Client(timeout=_TIMEOUT, follow_redirects=True) as client:
        response = client.get(url)

    # Capture redirect chain
    for r in response.history:
        redirect_chain.append(str(r.url))

    final_url = str(response.url)
    https_used = final_url.startswith("https://")
    status_code = response.status_code

    # Extract security headers (lowercase keys)
    response_headers = {k.lower(): v for k, v in response.headers.items()}
    security_headers = {
        h: response_headers[h] for h in _SECURITY_HEADERS if h in response_headers
    }

    server = response_headers.get("server")
    content_type = response_headers.get("content-type")

    evidence = HTTPEvidence(
        final_url=final_url,
        status_code=status_code,
        https_used=https_used,
        redirect_chain=redirect_chain,
        security_headers=security_headers,
        server=server,
        content_type=content_type,
    )

    missing_headers = [h for h in _SECURITY_HEADERS if h not in security_headers]
    if missing_headers:
        status = CollectorStatus.PARTIAL
        summary = (
            f"HTTP {status_code} at {final_url}. "
            f"Missing security headers: {', '.join(missing_headers)}."
        )
    else:
        status = CollectorStatus.OK
        summary = f"HTTP {status_code} at {final_url}. All key security headers present."

    if not https_used:
        status = CollectorStatus.PARTIAL
        summary = f"Final URL uses plain HTTP (not HTTPS): {final_url}. " + summary

    return CollectorResult(
        name=_COLLECTOR_NAME,
        status=status,
        summary=summary,
        payload=evidence,
    )
