"""Evaluator registry and dispatcher."""

from __future__ import annotations

import logging

from isrm.assess.evaluators.http import evaluate_http
from isrm.assess.evaluators.tls import evaluate_tls
from isrm.assess.evaluators.virustotal import evaluate_virustotal
from isrm.config import Settings
from isrm.models import CollectorResult, EvaluatedFinding

logger = logging.getLogger(__name__)

_REGISTRY = {
    "tls": evaluate_tls,
    "virustotal": evaluate_virustotal,
    "http": evaluate_http,
}


def evaluate(result: CollectorResult, settings: Settings) -> EvaluatedFinding:
    """Dispatch a collector result to the matching evaluator.

    Falls back to a conservative unknown-collector finding if no evaluator is registered.
    """
    fn = _REGISTRY.get(result.name)
    if fn is not None:
        return fn(result, settings)

    logger.warning("No evaluator registered for collector %r — using fallback", result.name)
    return EvaluatedFinding(
        collector=result.name,
        score=50,
        explanation=f"No evaluator is registered for collector '{result.name}'.",
        data_gap=True,
        confidence=20,
    )
