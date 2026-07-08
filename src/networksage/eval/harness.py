"""Eval harness for NetworkSage-X."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from networksage.agents.graph import run_alert
from networksage.clients.hf_client import HFClient
from networksage.observability.logger import DecisionLogger
from networksage.rag.knowledge_base import seed_default_knowledge_base
from networksage.schemas.models import AttackCategory, NetworkAlert, PipelineState, Severity


@dataclass
class EvalCase:
    name: str
    alert: NetworkAlert
    expected_severity: Severity
    expected_category: AttackCategory
    expected_techniques: list[str] = field(default_factory=list)
    expected_iocs: list[str] = field(default_factory=list)


@dataclass
class EvalResult:
    case_name: str
    passed: bool
    severity_correct: bool
    category_correct: bool
    technique_recall_at_k: float
    ioc_recall: float
    attribution_chain_size: int
    total_latency_ms: int
    notes: list[str] = field(default_factory=list)


def _score_severity(state: PipelineState, expected: Severity) -> bool:
    return bool(state.triage and state.triage.severity == expected)


def _score_category(state: PipelineState, expected: AttackCategory) -> bool:
    return bool(state.triage and state.triage.category == expected)


def _score_techniques(state: PipelineState, expected: list[str], k: int = 3) -> float:
    if not expected:
        return 1.0
    if not state.investigation:
        return 0.0
    predicted = [t["id"] for t in state.investigation.mitre_techniques[:k]]
    hits = sum(1 for t in expected if any(p.upper() == t.upper() for p in predicted))
    return hits / len(expected)


def _score_iocs(state: PipelineState, expected: list[str]) -> float:
    if not expected:
        return 1.0
    if not state.triage:
        return 0.0
    extracted = {i.value.lower() for i in state.triage.indicators}
    expected_set = {e.lower() for e in expected}
    if not expected_set:
        return 1.0
    return len(extracted & expected_set) / len(expected_set)


def run_eval_case(case: EvalCase, hf: HFClient, kb: Any) -> EvalResult:
    state = run_alert(case.alert, hf, kb, DecisionLogger())
    severity_correct = _score_severity(state, case.expected_severity)
    category_correct = _score_category(state, case.expected_category)
    technique_recall = _score_techniques(state, case.expected_techniques)
    ioc_recall = _score_iocs(state, case.expected_iocs)
    attribution_size = len(state.all_attribution())
    total_latency = sum([state.triage.latency_ms if state.triage else 0, state.enrichment.latency_ms if state.enrichment else 0, state.investigation.latency_ms if state.investigation else 0, state.response.latency_ms if state.response else 0])
    notes: list[str] = []
    if state.error:
        notes.append(f"error: {state.error}")
    passed = severity_correct and category_correct and (technique_recall >= 0.5) and (ioc_recall >= 0.5)
    return EvalResult(case_name=case.name, passed=passed, severity_correct=severity_correct, category_correct=category_correct, technique_recall_at_k=technique_recall, ioc_recall=ioc_recall, attribution_chain_size=attribution_size, total_latency_ms=total_latency, notes=notes)


def run_eval_suite(cases: list[EvalCase], hf: HFClient | None = None) -> list[EvalResult]:
    hf = hf or HFClient()
    kb = seed_default_knowledge_base(hf)
    return [run_eval_case(case, hf, kb) for case in cases]


def summarize(results: list[EvalResult]) -> dict[str, Any]:
    if not results:
        return {"cases": 0}
    n = len(results)
    return {
        "cases": n,
        "passed": sum(1 for r in results if r.passed),
        "pass_rate": sum(1 for r in results if r.passed) / n,
        "severity_accuracy": sum(1 for r in results if r.severity_correct) / n,
        "category_accuracy": sum(1 for r in results if r.category_correct) / n,
        "mean_technique_recall": sum(r.technique_recall_at_k for r in results) / n,
        "mean_ioc_recall": sum(r.ioc_recall for r in results) / n,
        "mean_attribution_chain_size": sum(r.attribution_chain_size for r in results) / n,
        "mean_total_latency_ms": sum(r.total_latency_ms for r in results) / n,
    }