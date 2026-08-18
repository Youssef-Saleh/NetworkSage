"""Investigation Agent."""

from __future__ import annotations

import time

from networksage.rag.knowledge_base import KnowledgeBase
from networksage.schemas.models import (
    AttributionRef,
    EnrichmentResult,
    InvestigationResult,
    RetrievedDoc,
    TriageResult,
)


def _build_query(triage: TriageResult, enrichment: EnrichmentResult) -> str:
    iocs_with_type = " ".join(f"{i.value}({i.type.value})" for i in triage.indicators)
    return (
        f"Category: {triage.category.value}. Severity: {triage.severity.value}. "
        f"Indicators: {iocs_with_type or 'none'}. "
        f"Threat intel verdicts: {enrichment.rationale}."
    )


def _extract_cves(triage: TriageResult) -> list[str]:
    return [i.value.upper() for i in triage.indicators if i.type.value == "cve"]


def _select_techniques(retrieved: list[RetrievedDoc], candidates: list[str], top_n: int = 3) -> list[dict]:
    by_id: dict[str, RetrievedDoc] = {d.doc_id: d for d in retrieved}
    selected: list[dict] = []
    for tid in candidates:
        if tid in by_id:
            doc = by_id[tid]
            selected.append({"id": tid, "title": doc.title, "score": doc.score})
        if len(selected) >= top_n:
            break
    if len(selected) < top_n:
        for d in retrieved:
            if any(s["id"] == d.doc_id for s in selected):
                continue
            if d.doc_id.startswith("T"):
                selected.append({"id": d.doc_id, "title": d.title, "score": d.score})
            if len(selected) >= top_n:
                break
    if len(selected) < top_n:
        for tid in candidates:
            if any(s["id"] == tid for s in selected):
                continue
            selected.append({"id": tid, "title": tid, "score": 0.5})
            if len(selected) >= top_n:
                break
    return selected


def investigate(triage: TriageResult, enrichment: EnrichmentResult, knowledge_base: KnowledgeBase, top_k: int = 5) -> InvestigationResult:
    start = time.perf_counter()
    query = _build_query(triage, enrichment)
    retrieved = knowledge_base.retrieve(query, top_k=top_k)
    selected_techniques = _select_techniques(retrieved, triage.candidate_mitre_techniques)
    cves_found = _extract_cves(triage)
    cve_lookups: list[dict[str, str | float]] = []
    for cve in cves_found:
        docs = knowledge_base.retrieve(f"CVE exploitation {cve}", top_k=1)
        if docs:
            cve_lookups.append({"id": cve, "title": docs[0].title, "score": docs[0].score})
    investigation_notes = (
        f"Alert categorized as {triage.category.value} with severity {triage.severity.value}. "
        f"Top MITRE technique match: {selected_techniques[0]['id'] if selected_techniques else 'none'} "
        f"({selected_techniques[0]['title'] if selected_techniques else ''}). "
        f"{len(cve_lookups)} CVE references found. Threat intel signal: {enrichment.rationale}."
    )
    attribution: list[AttributionRef] = []
    for d in retrieved:
        attribution.append(AttributionRef(kind="mitre" if d.source == "mitre-attack" else "cve", ref_id=d.doc_id, snippet=d.snippet[:120], weight=d.score))
    for c in cve_lookups:
        attribution.append(AttributionRef(kind="cve", ref_id=str(c["id"]), snippet=str(c["title"]), weight=float(c["score"])))
    latency_ms = int((time.perf_counter() - start) * 1000)
    return InvestigationResult(
        retrieved_docs=retrieved,
        mitre_techniques=selected_techniques,
        cves=cve_lookups,
        investigation_notes=investigation_notes,
        attribution=attribution,
        latency_ms=latency_ms,
    )