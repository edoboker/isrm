"""LLM judge: converts an EvidenceBundle into a structured RiskReport via OpenRouter."""

from __future__ import annotations

import json
import logging
from typing import Any

from openai import OpenAI

from isrm.config import Settings
from isrm.models import EvidenceBundle, JudgeFinding, RiskLabel, RiskReport

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """\
You are a senior security risk assessor specializing in cloud workload egress security.

Your task is to evaluate whether a cloud workload should be permitted to communicate with an \
external URL, based on collected technical evidence.

You will receive an EvidenceBundle as JSON containing a list of collector results. \
Each collector has a name, a status, a summary, and optionally a typed payload.

Rules:
- Produce exactly one finding per collector result in the evidence bundle. Do not invent findings \
for collectors that are not present.
- Name each finding after its collector (e.g. "tls", "virustotal", "http").
- If a collector status is "failed" or "data_unavailable", reflect that uncertainty in its \
score_contribution (treat it as elevated risk) and set data_gap to true. Do not add a separate \
missing-data finding.
- Do not invent facts not present in the evidence.
- Be concise but auditable.

Output a JSON object with exactly this structure:
{
  "score": <integer 0-100, overall composite>,
  "label": <"Low"|"Medium"|"High"|"Critical">,
  "findings": [
    {
      "dimension": <collector name, e.g. "tls">,
      "score_contribution": <integer 0-100, risk from this collector alone>,
      "explanation": <string>,
      "data_gap": <boolean>
    }
  ],
  "rationale": <string, 2-4 sentences summarising the overall judgement>,
  "assumptions": [<string>, ...],
  "data_gaps": [<string>, ...],
  "confidence": <integer 0-100>
}

Score guide:
  0–25   = Low risk
  26–50  = Medium risk
  51–75  = High risk
  76–100 = Critical risk
"""


def judge(bundle: EvidenceBundle, settings: Settings) -> RiskReport:
    """Call the LLM judge to produce a RiskReport from collected evidence.

    Args:
        bundle: All collector results for the target.
        settings: Application settings (API key, model).

    Returns:
        A validated RiskReport.

    Raises:
        ValueError: If the judge returns invalid or unparseable output.
    """
    client = OpenAI(
        api_key=settings.openrouter_api_key,
        base_url="https://openrouter.ai/api/v1",
    )

    evidence_json = bundle.model_dump_json(indent=2)
    logger.debug("Sending evidence bundle to judge (%d bytes)", len(evidence_json))
    logger.debug("Evidence bundle:\n%s", evidence_json)

    create_kwargs = {
        "model": settings.openrouter_model,
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"Assess the risk of connecting to this URL.\n\n"
                    f"Evidence bundle:\n```json\n{evidence_json}\n```"
                ),
            },
        ],
        "response_format": {"type": "json_object"},
        "temperature": 0.1,
    }
    if settings.openrouter_max_tokens is not None:
        create_kwargs["max_tokens"] = settings.openrouter_max_tokens

    response = client.chat.completions.create(**create_kwargs)

    raw = response.choices[0].message.content
    if not raw:
        raise ValueError("Judge returned an empty response.")

    logger.debug("Judge raw response: %s", raw[:500])

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Judge response is not valid JSON: {exc}") from exc

    return _parse_report(bundle.target.original_input, data)


def _parse_report(target: str, data: dict[str, Any]) -> RiskReport:
    """Parse the judge's raw JSON dict into a validated RiskReport.

    Args:
        target: The original URL string.
        data: Raw JSON dict from the judge.

    Returns:
        A validated RiskReport.

    Raises:
        ValueError: If required fields are missing or invalid.
    """
    try:
        score = int(data["score"])
        label_raw = str(data["label"])
        label = RiskLabel(label_raw)
        rationale = str(data.get("rationale", ""))
        confidence = int(data.get("confidence", 50))

        assumptions: list[str] = [str(a) for a in (data.get("assumptions") or [])]
        data_gaps: list[str] = [str(g) for g in (data.get("data_gaps") or [])]

        findings: list[JudgeFinding] = []
        for f in data.get("findings") or []:
            findings.append(
                JudgeFinding(
                    dimension=str(f["dimension"]),
                    score_contribution=int(f["score_contribution"]),
                    explanation=str(f["explanation"]),
                    data_gap=bool(f.get("data_gap", False)),
                )
            )
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
