"""Pydantic schemas for NetworkSage-X.

Every agent reads a typed input and writes a typed output. The LangGraph state
holds these objects, so the entire pipeline is schema-validated end to end.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ---------- Enums ----------


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AttackCategory(str, Enum):
    PHISHING = "phishing"
    MALWARE = "malware"
    COMMAND_AND_CONTROL = "c2"
    EXFILTRATION = "exfiltration"
    LATERAL_MOVEMENT = "lateral_movement"
    INITIAL_ACCESS = "initial_access"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    RECONNAISSANCE = "reconnaissance"
    IMPACT = "impact"
    UNKNOWN = "unknown"


class AlertSource(str, Enum):
    SURICATA = "suricata"
    ZEEK = "zeek"
    WAZUH = "wazuh"
    SPLUNK = "splunk"
    ELASTIC = "elastic"
    GENERIC = "generic"


# ---------- Indicator types ----------


class IndicatorType(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    SHA256 = "sha256"
    SHA1 = "sha1"
    MD5 = "md5"
    EMAIL = "email"
    CVE = "cve"
    MITRE_TECHNIQUE = "mitre_technique"


class Indicator(BaseModel):
    """Single extracted indicator of compromise."""

    model_config = ConfigDict(frozen=False, str_strip_whitespace=True)

    value: str = Field(..., description="Raw indicator value")
    type: IndicatorType
    confidence: float = Field(..., ge=0.0, le=1.0)
    source_text: str | None = None
    source_span: tuple[int, int] | None = None


# ---------- Attestation ----------


class AttributionRef(BaseModel):
    """Single evidence reference backing an agent decision.

    Every non-trivial decision in the pipeline must carry one or more
    AttributionRef instances. This is the 'attribution layer' that ties
    back to the XAI thesis work.
    """

    kind: str = Field(..., description="ioc | cve | mitre | threat_intel | alert_field | rule_match")
    ref_id: str
    snippet: str | None = None
    weight: float = Field(1.0, ge=0.0, le=1.0)


# ---------- Input alert ----------


class NetworkAlert(BaseModel):
    """Normalized security alert input."""

    model_config = ConfigDict(extra="allow", str_strip_whitespace=True)

    alert_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: AlertSource = AlertSource.GENERIC
    title: str
    description: str = ""
    raw: dict[str, Any] = Field(default_factory=dict)

    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None
    user: str | None = None
    host: str | None = None
    file_hash: str | None = None
    destination_domain: str | None = None
    url: str | None = None

    @field_validator("alert_id")
    @classmethod
    def _strip_alert_id(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("alert_id must be non-empty")
        return v.strip()


# ---------- Per-agent I/O ----------


class TriageResult(BaseModel):
    severity: Severity
    severity_confidence: float = Field(..., ge=0.0, le=1.0)
    category: AttackCategory
    category_confidence: float = Field(..., ge=0.0, le=1.0)
    indicators: list[Indicator] = Field(default_factory=list)
    candidate_mitre_techniques: list[str] = Field(default_factory=list)
    attribution: list[AttributionRef] = Field(default_factory=list)
    rationale: str = ""
    latency_ms: int = 0


class ThreatIntelHit(BaseModel):
    provider: str
    indicator: str
    verdict: str
    score: float | None = Field(None, ge=0.0, le=100.0)
    details: dict[str, Any] = Field(default_factory=dict)


class EnrichmentResult(BaseModel):
    hits: list[ThreatIntelHit] = Field(default_factory=list)
    enriched_indicators: dict[str, dict[str, Any]] = Field(default_factory=dict)
    attribution: list[AttributionRef] = Field(default_factory=list)
    providers_queried: list[str] = Field(default_factory=list)
    providers_skipped: list[str] = Field(default_factory=list)
    rationale: str = ""
    latency_ms: int = 0


class RetrievedDoc(BaseModel):
    source: str
    doc_id: str
    title: str
    snippet: str
    score: float = Field(..., ge=0.0, le=1.0)


class InvestigationResult(BaseModel):
    retrieved_docs: list[RetrievedDoc] = Field(default_factory=list)
    mitre_techniques: list[dict[str, Any]] = Field(default_factory=list)
    cves: list[dict[str, Any]] = Field(default_factory=list)
    investigation_notes: str = ""
    attribution: list[AttributionRef] = Field(default_factory=list)
    latency_ms: int = 0


class RecommendedAction(BaseModel):
    action: str
    target: str
    rationale: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    automation_safe: bool = False


class ResponseResult(BaseModel):
    executive_summary: str
    detailed_findings: str
    recommended_actions: list[RecommendedAction] = Field(default_factory=list)
    citations: list[AttributionRef] = Field(default_factory=list)
    full_attribution_chain: list[AttributionRef] = Field(default_factory=list)
    report_markdown: str = ""
    latency_ms: int = 0


class PipelineState(BaseModel):
    alert: NetworkAlert
    triage: TriageResult | None = None
    enrichment: EnrichmentResult | None = None
    investigation: InvestigationResult | None = None
    response: ResponseResult | None = None
    error: str | None = None
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None

    model_config = ConfigDict(arbitrary_types_allowed=True)

    def all_attribution(self) -> list[AttributionRef]:
        out: list[AttributionRef] = []
        if self.triage:
            out.extend(self.triage.attribution)
        if self.enrichment:
            out.extend(self.enrichment.attribution)
        if self.investigation:
            out.extend(self.investigation.attribution)
        if self.response:
            out.extend(self.response.citations)
        return out