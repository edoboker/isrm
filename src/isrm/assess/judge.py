"""LLM judge: synthesizes evaluated findings into a final RiskReport."""

from __future__ import annotations

import json
import logging
from typing import Any

from isrm.assess._llm import call_llm, load_prompt
from isrm.config import Settings
from isrm.models import AssessmentTarget, EvaluatedFinding, RiskLabel, RiskReport

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = load_prompt("judge.txt")


def judge(
    target: AssessmentTarget,
    findings: list[EvaluatedFinding],
    settings: Settings,
) -> RiskReport:
    """Synthesize evaluated findings into a final RiskReport.

    Args:
        target: The normalized assessment target.
        findings: Pre-scored findings from each evaluator.
        settings: Application settings.

    Returns:
        A validated RiskReport.
    """
    findings_json = json.dumps(
        [f.model_dump() for f in findings],
        indent=2,
    )
    logger.debug("Sending findings to judge:\n%s", findings_json)

    data = call_llm(
        system_prompt=_SYSTEM_PROMPT,
        user_content=(
            f"Target: {target.original_input}\n\n"
            f"Evaluated findings:\n```json\n{findings_json}\n```"
        ),
        settings=settings,
    )

    return _build_report(target.original_input, findings, data)


def _build_report(
    target: str,
    findings: list[EvaluatedFinding],
    data: dict[str, Any],
) -> RiskReport:
    try:
        score = int(data["score"])
        label = RiskLabel(str(data["label"]))
        rationale = str(data.get("rationale", ""))
        confidence = int(data.get("confidence", 50))
        assumptions: list[str] = [str(a) for a in (data.get("assumptions") or [])]
        data_gaps: list[str] = [str(g) for g in (data.get("data_gaps") or [])]
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"Judge response missing or invalid field: {exc}") from exc

    return RiskReport(
        target=target,
        score=score,
        label=label,
        findings=findings,
        rationale=rationale,
        assumptions=assumptions,
        data_gaps=data_gaps,
        confidence=confidence,
    )
