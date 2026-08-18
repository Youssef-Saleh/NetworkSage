"""Structured logging for agent decisions (attribution layer hook)."""

from __future__ import annotations

import json
import logging
import sys
import uuid
from datetime import UTC, datetime
from typing import Any

log = logging.getLogger("networksage.decisions")
if not log.handlers:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(message)s"))
    log.addHandler(handler)
log.setLevel(logging.INFO)


class DecisionLogger:
    def __init__(self, run_id: str | None = None) -> None:
        self.run_id = run_id or str(uuid.uuid4())
        self.decisions: list[dict[str, Any]] = []

    def log_agent_decision(self, agent_name: str, alert_id: str, result: Any) -> None:
        record = {
            "ts": datetime.now(UTC).isoformat(),
            "run_id": self.run_id,
            "agent": agent_name,
            "alert_id": alert_id,
            "result": _safe_serialize(result),
        }
        self.decisions.append(record)
        log.info(json.dumps(record, default=str))

    def to_jsonl(self) -> str:
        return "\n".join(json.dumps(d, default=str) for d in self.decisions)


def _safe_serialize(obj: Any) -> Any:
    if obj is None:
        return None
    if hasattr(obj, "model_dump"):
        return obj.model_dump(mode="json")
    if isinstance(obj, list):
        return [_safe_serialize(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _safe_serialize(v) for k, v in obj.items()}
    return obj