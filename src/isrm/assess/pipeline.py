"""Assessment pipeline: normalize → collect → evaluate → judge → report."""

from __future__ import annotations

import logging
from urllib.parse import urlparse

from isrm.assess.collectors.http import collect_http
from isrm.assess.collectors.threat_history import collect_threat_history
from isrm.assess.collectors.tls import collect_tls
from isrm.assess.collectors.virustotal import collect_virustotal
from isrm.assess.evaluators import evaluate
from isrm.assess.judge import judge
from isrm.config import Settings
from isrm.models import AssessmentTarget, RiskReport

logger = logging.getLogger(__name__)


def _normalize(url: str) -> AssessmentTarget:
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
    """Run the full assessment pipeline for a URL."""
    target = _normalize(url)
    logger.info("Target normalized: hostname=%s scheme=%s", target.hostname, target.scheme)

    collector_results = []

    logger.info("Running TLS collector")
    collector_results.append(collect_tls(target.hostname))

    logger.info("Running VirusTotal collector")
    collector_results.append(collect_virustotal(target.hostname, settings.virustotal_api_key))

    logger.info("Running HTTP collector")
    collector_results.append(collect_http(target.url))

    logger.info("Running threat-history collector")
    collector_results.append(collect_threat_history(target.hostname, settings))

    logger.info("Running evaluators")
    findings = []
    for result in collector_results:
        logger.info("Evaluating %s", result.name)
        findings.append(evaluate(result, settings))
        logger.info("%s score=%d confidence=%d", result.name, findings[-1].score, findings[-1].confidence)

    logger.info("Calling judge")
    report = judge(target, findings, settings)
    logger.info("Assessment complete: score=%d label=%s", report.score, report.label)

    return report
