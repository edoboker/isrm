"""Threat-history agentic collector."""

from __future__ import annotations

import logging
from urllib.parse import urlparse

from isrm.assess.agents.threat_history import run_agent
from isrm.config import Settings, load_settings
from isrm.models import CollectorResult, CollectorStatus

logger = logging.getLogger(__name__)

_COLLECTOR_NAME = "threat_history"


def collect_threat_history(hostname: str, settings: Settings) -> CollectorResult:
    """Research public threat history for a hostname using the Pydantic AI agent.

    Args:
        hostname: Bare hostname or FQDN to research.
        settings: Application settings.

    Returns:
        A CollectorResult containing ThreatHistoryEvidence.
    """
    if not settings.tavily_api_key:
        return CollectorResult(
            name=_COLLECTOR_NAME,
            status=CollectorStatus.DATA_UNAVAILABLE,
            summary="Tavily API key not configured (TAVILY_API_KEY unset).",
            errors=["TAVILY_API_KEY is not set"],
        )

    try:
        evidence = run_agent(hostname, settings)
    except Exception as exc:
        logger.warning("Threat-history agent failed for %s: %s", hostname, exc)
        return CollectorResult(
            name=_COLLECTOR_NAME,
            status=CollectorStatus.FAILED,
            summary=f"Threat-history research failed: {exc}",
            errors=[str(exc)],
        )

    scope_str = evidence.strongest_scope.value if evidence.strongest_scope else "none"
    if evidence.abuse_found:
        cats = ", ".join(evidence.categories) if evidence.categories else "unspecified"
        summary = (
            f"Public abuse evidence found for {hostname}: {cats}. "
            f"Strongest scope: {scope_str}. "
            f"{len(evidence.sources)} source(s). Confidence: {evidence.confidence}%."
        )
        status = CollectorStatus.OK
    else:
        summary = (
            f"No public abuse evidence found for {hostname} "
            f"({len(evidence.searched_queries)} queries, strongest scope: {scope_str}). "
            f"Confidence: {evidence.confidence}%."
        )
        status = CollectorStatus.OK

    return CollectorResult(
        name=_COLLECTOR_NAME,
        status=status,
        summary=summary,
        payload=evidence,
    )


def _parse_hostname(target: str) -> str:
    """Extract hostname from a URL or return the input as-is for a bare hostname."""
    if "://" in target:
        parsed = urlparse(target)
        if parsed.hostname:
            return parsed.hostname
    return target


if __name__ == "__main__":
    import logging
    import sys

    logging.basicConfig(level=logging.INFO, stream=sys.stderr)
    if len(sys.argv) < 2:
        print("Usage: python -m isrm.assess.collectors.threat_history <hostname-or-url>")
        sys.exit(1)

    _settings = load_settings()
    _hostname = _parse_hostname(sys.argv[1])
    _result = collect_threat_history(_hostname, _settings)
    print(_result.model_dump_json(indent=2))
