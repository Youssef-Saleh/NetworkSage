"""LangGraph state machine wiring the four NetworkSage-X agents."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph

from networksage.agents.enrichment import enrich_indicators
from networksage.agents.investigation import investigate
from networksage.agents.response import draft_response
from networksage.agents.triage import triage_alert
from networksage.clients.hf_client import HFClient
from networksage.observability.logger import DecisionLogger
from networksage.rag.knowledge_base import KnowledgeBase, seed_default_knowledge_base
from networksage.schemas.models import PipelineState

log = logging.getLogger(__name__)


class GraphState(TypedDict, total=False):
    """LangGraph state: a serialized PipelineState that round-trips through agents.

    Each agent node receives a dict (the LangGraph runtime contract), deserializes
    it into a PipelineState, runs its work, and serializes back. TypedDict gives the
    type checker a real shape to validate instead of `dict[str, Any]`.
    """

    alert: dict[str, Any]
    triage: dict[str, Any] | None
    enrichment: dict[str, Any] | None
    investigation: dict[str, Any] | None
    response: dict[str, Any] | None
    error: str | None
    started_at: str | None
    completed_at: str | None


def _state_to_dict(state: PipelineState) -> GraphState:
    return state.model_dump(mode="json")  # type: ignore[return-value]


def _dict_to_state(d: GraphState) -> PipelineState:
    return PipelineState.model_validate(d)


def _node_triage(state: GraphState, hf: HFClient, logger: DecisionLogger) -> GraphState:
    s = _dict_to_state(state)
    log.info("triage:start alert_id=%s", s.alert.alert_id)
    triage = triage_alert(s.alert, hf)
    logger.log_agent_decision("triage", s.alert.alert_id, triage)
    s.triage = triage
    return _state_to_dict(s)


def _node_enrichment(state: GraphState, logger: DecisionLogger) -> GraphState:
    s = _dict_to_state(state)
    log.info("enrichment:start alert_id=%s", s.alert.alert_id)
    if s.triage is None:
        s.error = "triage step did not produce a result"
        return _state_to_dict(s)
    enrichment = enrich_indicators(s.triage)
    logger.log_agent_decision("enrichment", s.alert.alert_id, enrichment)
    s.enrichment = enrichment
    return _state_to_dict(s)


def _node_investigation(state: GraphState, knowledge_base: KnowledgeBase, logger: DecisionLogger) -> GraphState:
    s = _dict_to_state(state)
    log.info("investigation:start alert_id=%s", s.alert.alert_id)
    if s.triage is None or s.enrichment is None:
        s.error = "upstream steps missing before investigation"
        return _state_to_dict(s)
    investigation = investigate(s.triage, s.enrichment, knowledge_base)
    logger.log_agent_decision("investigation", s.alert.alert_id, investigation)
    s.investigation = investigation
    return _state_to_dict(s)


def _node_response(state: GraphState, logger: DecisionLogger) -> GraphState:
    s = _dict_to_state(state)
    log.info("response:start alert_id=%s", s.alert.alert_id)
    try:
        response = draft_response(s)
    except ValueError as e:
        s.error = str(e)
        s.completed_at = datetime.now(UTC)
        return _state_to_dict(s)
    logger.log_agent_decision("response", s.alert.alert_id, response)
    s.response = response
    s.completed_at = datetime.now(UTC)
    return _state_to_dict(s)


def build_graph(hf_client: HFClient, knowledge_base: KnowledgeBase, logger: DecisionLogger | None = None) -> Any:
    logger = logger or DecisionLogger()
    g: StateGraph[GraphState] = StateGraph(GraphState)

    def triage_fn(state: GraphState) -> GraphState:
        return _node_triage(state, hf_client, logger)

    def enrich_fn(state: GraphState) -> GraphState:
        return _node_enrichment(state, logger)

    def inv_fn(state: GraphState) -> GraphState:
        return _node_investigation(state, knowledge_base, logger)

    def resp_fn(state: GraphState) -> GraphState:
        return _node_response(state, logger)

    g.add_node("triage", triage_fn)
    g.add_node("enrichment", enrich_fn)
    g.add_node("investigation", inv_fn)
    g.add_node("response", resp_fn)
    g.add_edge(START, "triage")
    g.add_edge("triage", "enrichment")
    g.add_edge("enrichment", "investigation")
    g.add_edge("investigation", "response")
    g.add_edge("response", END)
    return g.compile()


def run_alert(alert, hf_client: HFClient | None = None, knowledge_base: KnowledgeBase | None = None, logger: DecisionLogger | None = None) -> PipelineState:
    hf_client = hf_client or HFClient()
    knowledge_base = knowledge_base or seed_default_knowledge_base(hf_client)
    logger = logger or DecisionLogger()
    graph = build_graph(hf_client, knowledge_base, logger)
    initial_state = PipelineState(alert=alert)
    result = graph.invoke(_state_to_dict(initial_state))
    return _dict_to_state(result)