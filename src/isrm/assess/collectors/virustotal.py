"""VirusTotal threat reputation collector."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import httpx

from isrm.models import CollectorResult, CollectorStatus, VirusTotalEvidence

logger = logging.getLogger(__name__)

_COLLECTOR_NAME = "virustotal"
_BASE_URL = "https://www.virustotal.com/api/v3"
_TIMEOUT = 15


def collect_virustotal(hostname: str, api_key: str | None) -> CollectorResult:
    """Collect threat reputation data from VirusTotal for a hostname.

    Args:
        hostname: The hostname to look up.
        api_key: VirusTotal API key. If None, returns data_unavailable.

    Returns:
        A CollectorResult containing VirusTotalEvidence or a data_unavailable status.
    """
    if not api_key:
        return CollectorResult(
            name=_COLLECTOR_NAME,
            status=CollectorStatus.DATA_UNAVAILABLE,
            summary="VirusTotal API key not configured (VIRUSTOTAL_API_KEY unset).",
            errors=["VIRUSTOTAL_API_KEY is not set"],
        )

    try:
        return _do_collect(hostname, api_key)
    except httpx.TimeoutException as exc:
        logger.warning("VirusTotal request timed out for %s: %s", hostname, exc)
        return CollectorResult(
            name=_COLLECTOR_NAME,
            status=CollectorStatus.FAILED,
            summary="VirusTotal request timed out.",
            errors=[str(exc)],
        )
    except Exception as exc:
        logger.warning("VirusTotal collector failed for %s: %s", hostname, exc)
        return CollectorResult(
            name=_COLLECTOR_NAME,
            status=CollectorStatus.FAILED,
            summary=f"VirusTotal lookup failed: {exc}",
            errors=[str(exc)],
        )


def _do_collect(hostname: str, api_key: str) -> CollectorResult:
    url = f"{_BASE_URL}/domains/{hostname}"
    headers = {"x-apikey": api_key}

    with httpx.Client(timeout=_TIMEOUT) as client:
        response = client.get(url, headers=headers)

    if response.status_code == 404:
        return CollectorResult(
            name=_COLLECTOR_NAME,
            status=CollectorStatus.DATA_UNAVAILABLE,
            summary=f"Domain {hostname!r} not found in VirusTotal.",
        )

    if response.status_code == 403:
        return CollectorResult(
            name=_COLLECTOR_NAME,
            status=CollectorStatus.FAILED,
            summary="VirusTotal API key invalid or quota exceeded.",
            errors=["HTTP 403 from VirusTotal"],
        )

    response.raise_for_status()
    data = response.json()

    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    reputation = attrs.get("reputation")
    categories: dict[str, str] = attrs.get("categories", {})

    last_analysis_ts = attrs.get("last_analysis_date")
    last_analysis_date: datetime | None = None
    if last_analysis_ts:
        last_analysis_date = datetime.fromtimestamp(last_analysis_ts, tz=timezone.utc)

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    evidence = VirusTotalEvidence(
        malicious=malicious,
        suspicious=suspicious,
        harmless=harmless,
        undetected=undetected,
        reputation=reputation,
        last_analysis_date=last_analysis_date,
        categories=categories,
    )

    if malicious > 0:
        status = CollectorStatus.OK
        summary = (
            f"VirusTotal: {malicious} malicious, {suspicious} suspicious detections. "
            f"Reputation score: {reputation}."
        )
    elif suspicious > 0:
        status = CollectorStatus.OK
        summary = f"VirusTotal: {suspicious} suspicious detections. Reputation score: {reputation}."
    else:
        status = CollectorStatus.OK
        summary = (
            f"VirusTotal: no malicious detections ({harmless} harmless, "
            f"{undetected} undetected). Reputation score: {reputation}."
        )

    return CollectorResult(
        name=_COLLECTOR_NAME,
        status=status,
        summary=summary,
        payload=evidence,
    )
