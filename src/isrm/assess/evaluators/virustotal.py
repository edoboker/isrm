"""VirusTotal evaluator."""

from __future__ import annotations

import logging

from isrm.assess._llm import call_llm, load_prompt
from isrm.config import Settings
from isrm.models import CollectorResult, EvaluatedFinding

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = load_prompt("evaluator_virustotal.txt")


def evaluate_virustotal(result: CollectorResult, settings: Settings) -> EvaluatedFinding:
    """Evaluate threat reputation risk from a VirusTotal collector result."""
    data = call_llm(
        system_prompt=_SYSTEM_PROMPT,
        user_content=result.model_dump_json(indent=2),
        settings=settings,
    )
    return EvaluatedFinding(
        collector="virustotal",
        score=int(data["score"]),
        explanation=str(data["explanation"]),
        data_gap=bool(data.get("data_gap", False)),
        confidence=int(data.get("confidence", 50)),
    )
