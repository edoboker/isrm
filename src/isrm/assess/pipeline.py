"""Assessment pipeline: normalize → collect → judge → report."""

from __future__ import annotations

import logging
from urllib.parse import urlparse

from isrm.assess.collectors.http import collect_http
from isrm.assess.collectors.tls import collect_tls
from isrm.assess.collectors.virustotal import collect_virustotal
from isrm.assess.judge import judge
from isrm.config import Settings
from isrm.models import AssessmentTarget, EvidenceBundle, RiskReport

logger = logging.getLogger(__name__)


def _normalize(url: str) -> AssessmentTarget:
    """Parse and normalize a URL string into an AssessmentTarget.

    Args:
        url: Raw URL string provided by the user.

    Returns:
        Normalized AssessmentTarget.

    Raises:
        ValueError: If the URL is missing a scheme or hostname.
    """
    parsed = urlparse(url)
    if not parsed.scheme:
        raise ValueError(f"URL must include a scheme (e.g. https://): {url!r}")
    if not parsed.hostname:
        raise ValueError(f"Could not extract a hostname from URL: {url!r}")
    return AssessmentTarget(
        original_input=url,
        url=url,
        hostname=parsed.hostname,
        scheme=parsed.scheme,
    )


def run_assessment(url: str, settings: Settings) -> RiskReport:
    """Run the full assessment pipeline for a URL.

    Args:
        url: The target URL to assess.
        settings: Application settings (API keys, model).

    Returns:
        A structured RiskReport.
    """
    target = _normalize(url)
    logger.info("Target normalized: hostname=%s scheme=%s", target.hostname, target.scheme)

    results = []

    logger.info("Running TLS collector")
    results.append(collect_tls(target.hostname))

    logger.info("Running VirusTotal collector")
    results.append(collect_virustotal(target.hostname, settings.virustotal_api_key))

    logger.info("Running HTTP collector")
    results.append(collect_http(target.url))

    bundle = EvidenceBundle(target=target, results=results)
    logger.info("Evidence collected from %d collectors", len(results))

    logger.info("Calling judge")
    report = judge(bundle, settings)
    logger.info("Assessment complete: score=%d label=%s", report.score, report.label)

    return report
