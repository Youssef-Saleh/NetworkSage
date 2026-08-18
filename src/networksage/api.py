"""FastAPI app exposing NetworkSage-X over HTTP."""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from networksage.agents.graph import _dict_to_state, _state_to_dict, build_graph
from networksage.clients.hf_client import HFClient
from networksage.observability.logger import DecisionLogger
from networksage.rag.knowledge_base import seed_default_knowledge_base
from networksage.schemas.models import NetworkAlert, PipelineState

logging.basicConfig(level=os.getenv("NETWORKSAGE_LOG_LEVEL", "INFO"))
log = logging.getLogger(__name__)


_state: dict[str, Any] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    hf = HFClient()
    kb = seed_default_knowledge_base(hf)
    graph = build_graph(hf, kb, DecisionLogger())
    _state["hf"] = hf
    _state["kb"] = kb
    _state["graph"] = graph
    log.info("NetworkSage-X ready (hf_configured=%s, kb_size=%d)", hf.is_configured(), kb.size())
    yield
    _state.clear()


app = FastAPI(title="NetworkSage-X", description="Multi-agent SOC analyst with RAG, eval harness, and explainable attribution.", version="0.1.0", lifespan=lifespan)


@app.get("/health")
async def health() -> dict[str, Any]:
    return {"status": "ok", "hf_configured": _state["hf"].is_configured(), "kb_size": _state["kb"].size()}


class AlertRequest(BaseModel):
    alert: NetworkAlert


class PipelineRunResponse(BaseModel):
    alert_id: str
    severity: str | None = None
    category: str | None = None
    indicators_count: int = 0
    techniques: list[str] = Field(default_factory=list)
    report_markdown: str | None = None
    latency_ms_total: int = 0


@app.post("/alerts", response_model=PipelineRunResponse)
async def post_alert(req: AlertRequest) -> PipelineRunResponse:
    graph = _state.get("graph")
    if graph is None:
        raise HTTPException(status_code=503, detail="graph not initialized")
    initial = PipelineState(alert=req.alert)
    raw = graph.invoke(_state_to_dict(initial))
    final = _dict_to_state(raw)
    if final.error:
        raise HTTPException(status_code=500, detail=final.error)
    return PipelineRunResponse(
        alert_id=final.alert.alert_id,
        severity=final.triage.severity.value if final.triage else None,
        category=final.triage.category.value if final.triage else None,
        indicators_count=len(final.triage.indicators) if final.triage else 0,
        techniques=final.investigation.mitre_techniques[0]["id"] if final.investigation and final.investigation.mitre_techniques else [],
        report_markdown=final.response.report_markdown if final.response else None,
        latency_ms_total=sum([final.triage.latency_ms if final.triage else 0, final.enrichment.latency_ms if final.enrichment else 0, final.investigation.latency_ms if final.investigation else 0, final.response.latency_ms if final.response else 0]),
    )