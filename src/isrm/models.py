"""Shared Pydantic v2 models for isrm."""

from __future__ import annotations

import enum
from datetime import datetime
from typing import Union

from pydantic import BaseModel, Field


class RiskLabel(str, enum.Enum):
    """Risk label derived from composite score."""

    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

    @classmethod
    def from_score(cls, score: int) -> "RiskLabel":
        """Return the label for a 0–100 composite score."""
        if score <= 25:
            return cls.LOW
        if score <= 50:
            return cls.MEDIUM
        if score <= 75:
            return cls.HIGH
        return cls.CRITICAL


class CollectorStatus(str, enum.Enum):
    """Outcome status of a single collector run."""

    OK = "ok"
    PARTIAL = "partial"
    FAILED = "failed"
    DATA_UNAVAILABLE = "data_unavailable"


# ---------------------------------------------------------------------------
# Evidence payloads
# ---------------------------------------------------------------------------


class TLSEvidence(BaseModel):
    """Evidence collected by the TLS/certificate collector."""

    connected: bool
    subject: str | None = None
    issuer: str | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None
    expired: bool | None = None
    hostname_match: bool | None = None
    chain_trusted: bool | None = None
    tls_version: str | None = None
    failure_reason: str | None = None


class VirusTotalEvidence(BaseModel):
    """Evidence collected by the VirusTotal collector."""

    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    reputation: int | None = None
    last_analysis_date: datetime | None = None
    categories: dict[str, str] = Field(default_factory=dict)


class HTTPEvidence(BaseModel):
    """Evidence collected by the HTTP collector."""

    final_url: str
    status_code: int | None = None
    https_used: bool = False
    redirect_chain: list[str] = Field(default_factory=list)
    security_headers: dict[str, str] = Field(default_factory=dict)
    server: str | None = None
    content_type: str | None = None


# ---------------------------------------------------------------------------
# Collector result wrapper
# ---------------------------------------------------------------------------

EvidencePayload = Union[TLSEvidence, VirusTotalEvidence, HTTPEvidence]


class CollectorResult(BaseModel):
    """Generic wrapper around one collector's output."""

    name: str
    status: CollectorStatus
    summary: str
    payload: EvidencePayload | None = None
    raw_text: str | None = None
    errors: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Evidence bundle
# ---------------------------------------------------------------------------


class AssessmentTarget(BaseModel):
    """Normalized user input."""

    original_input: str
    url: str
    hostname: str
    scheme: str


class EvidenceBundle(BaseModel):
    """All collector results for one assessment run."""

    target: AssessmentTarget
    results: list[CollectorResult] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Evaluator output
# ---------------------------------------------------------------------------


class EvaluatedFinding(BaseModel):
    """Risk finding produced by a per-collector evaluator."""

    collector: str
    score: int = Field(ge=0, le=100)
    explanation: str
    data_gap: bool = False
    confidence: int = Field(ge=0, le=100)


# ---------------------------------------------------------------------------
# Final report
# ---------------------------------------------------------------------------


class RiskReport(BaseModel):
    """Final structured risk report."""

    target: str
    score: int = Field(ge=0, le=100)
    label: RiskLabel
    findings: list[EvaluatedFinding] = Field(default_factory=list)
    rationale: str
    assumptions: list[str] = Field(default_factory=list)
    data_gaps: list[str] = Field(default_factory=list)
    confidence: int = Field(ge=0, le=100)
