"""HuggingFace Inference API client with deterministic fallback."""

from __future__ import annotations

import os
import re
from typing import Any

from tenacity import retry, retry_if_not_exception_type, stop_after_attempt, wait_exponential

try:
    from huggingface_hub import InferenceClient
    from huggingface_hub.errors import HfHubHTTPError
except ImportError:  # pragma: no cover
    InferenceClient = None  # type: ignore[assignment,misc]
    HfHubHTTPError = Exception  # type: ignore[assignment,misc]


def _is_auth_error(exc: BaseException) -> bool:
    if isinstance(exc, HfHubHTTPError):
        status = getattr(exc, "response", None)
        code = getattr(status, "status_code", None)
        if code in (401, 403):
            return True
    return False


_RETRYABLE = retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=8),
    retry=retry_if_not_exception_type((ValueError,)),
    reraise=True,
)


class HFClient:
    """Lazy-initialized HuggingFace Inference client with a no-key fallback."""

    _PLACEHOLDER_TOKENS = frozenset({"hf_xxx", "hf_xxx...", "your_token_here", ""})

    def __init__(self, token: str | None = None) -> None:
        raw = token or os.getenv("HF_TOKEN") or os.getenv("HUGGINGFACEHUB_API_TOKEN")
        self.token: str | None = raw if raw and raw.strip().lower() not in self._PLACEHOLDER_TOKENS else None
        self._client: Any | None = None
        self._auth_failed: bool = False

    @property
    def client(self) -> Any | None:
        if self._auth_failed:
            return None
        if self._client is None and InferenceClient is not None and self.token:
            self._client = InferenceClient(token=self.token)
        return self._client

    def is_configured(self) -> bool:
        return self.client is not None

    def _mark_auth_failed(self) -> None:
        self._auth_failed = True
        self._client = None

    @_RETRYABLE
    def zero_shot_classify(self, text: str, labels: list[str], model: str = "facebook/bart-large-mnli") -> dict[str, float]:
        if not self.is_configured():
            return _fallback_zero_shot(text, labels)
        assert self.client is not None
        try:
            result = self.client.zero_shot_classification(text=text, candidate_labels=labels, model=model)
        except Exception as e:
            if _is_auth_error(e):
                self._mark_auth_failed()
                raise ValueError(f"HF auth failed: {e}") from e
            raise
        return {item["label"]: float(item["score"]) for item in result}

    @_RETRYABLE
    def token_classify(self, text: str, model: str = "dslim/bert-base-NER") -> list[dict[str, Any]]:
        if not self.is_configured():
            return _fallback_token_classify(text)
        assert self.client is not None
        try:
            entities = self.client.token_classification(text=text, model=model)
        except Exception as e:
            if _is_auth_error(e):
                self._mark_auth_failed()
                raise ValueError(f"HF auth failed: {e}") from e
            raise
        return [
            {
                "entity_group": e.get("entity_group") or e.get("entity"),
                "word": e["word"],
                "score": float(e.get("score", 0.0)),
                "start": int(e.get("start", 0)),
                "end": int(e.get("end", 0)),
            }
            for e in entities
        ]

    @_RETRYABLE
    def feature_extraction(self, texts: list[str], model: str = "sentence-transformers/all-MiniLM-L6-v2") -> list[list[float]]:
        if not self.is_configured():
            return _fallback_embeddings(texts)
        assert self.client is not None
        try:
            embeddings = self.client.feature_extraction(text=texts, model=model)
        except Exception as e:
            if _is_auth_error(e):
                self._mark_auth_failed()
                raise ValueError(f"HF auth failed: {e}") from e
            raise
        if hasattr(embeddings, "tolist"):
            embeddings = embeddings.tolist()
        return embeddings

    @_RETRYABLE
    def chat(self, messages: list[dict[str, str]], model: str, max_tokens: int = 1024, temperature: float = 0.1, response_format: dict[str, str] | None = None) -> str:
        if not self.is_configured():
            return _fallback_chat(messages, model)
        assert self.client is not None
        kwargs: dict[str, Any] = {"model": model, "messages": messages, "max_tokens": max_tokens, "temperature": temperature}
        if response_format is not None:
            kwargs["response_format"] = response_format
        try:
            completion = self.client.chat_completion(**kwargs)
        except Exception as e:
            if _is_auth_error(e):
                self._mark_auth_failed()
                raise ValueError(f"HF auth failed: {e}") from e
            raise
        if isinstance(completion, dict):
            return str(completion["choices"][0]["message"]["content"])
        return str(completion.choices[0].message.content)


# ---------- Deterministic fallbacks ----------


_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE)
_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")


def _fallback_zero_shot(text: str, labels: list[str]) -> dict[str, float]:
    text_l = text.lower()
    scores: dict[str, float] = {}
    for label in labels:
        tokens = [t for t in label.lower().replace("_", " ").split() if len(t) > 2]
        if not tokens:
            scores[label] = 0.0
            continue
        hits = sum(1 for t in tokens if t in text_l)
        scores[label] = hits / len(tokens)
    total = sum(scores.values()) or 1.0
    return {k: v / total for k, v in scores.items()}


def _fallback_token_classify(text: str) -> list[dict[str, Any]]:
    spans: list[dict[str, Any]] = []
    for m in _IPV4.finditer(text):
        spans.append({"entity_group": "IPV4", "word": m.group(), "score": 0.95, "start": m.start(), "end": m.end()})
    for m in _SHA256.finditer(text):
        spans.append({"entity_group": "SHA256", "word": m.group(), "score": 0.95, "start": m.start(), "end": m.end()})
    for m in _CVE.finditer(text):
        spans.append({"entity_group": "CVE", "word": m.group().upper(), "score": 0.98, "start": m.start(), "end": m.end()})
    for m in _DOMAIN.finditer(text):
        spans.append({"entity_group": "DOMAIN", "word": m.group(), "score": 0.7, "start": m.start(), "end": m.end()})
    for m in _EMAIL.finditer(text):
        spans.append({"entity_group": "EMAIL", "word": m.group(), "score": 0.85, "start": m.start(), "end": m.end()})
    return spans


def _fallback_embeddings(texts: list[str]) -> list[list[float]]:
    import hashlib

    dim = 256
    out: list[list[float]] = []
    for text in texts:
        vec = [0.0] * dim
        for token in text.lower().split():
            digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
            h = int(digest[:8], 16) % dim
            vec[h] += 1.0
        norm = sum(v * v for v in vec) ** 0.5 or 1.0
        out.append([v / norm for v in vec])
    return out


def _fallback_chat(messages: list[dict[str, str]], model: str) -> str:
    import json

    last = messages[-1]["content"] if messages else ""
    return json.dumps(
        {
            "_fallback": True,
            "_model": model,
            "_echo": last[:200],
            "executive_summary": "Fallback summary: structured output unavailable without HF_TOKEN or local model server.",
            "detailed_findings": "Set HF_TOKEN in .env to enable real LLM-backed agent reasoning.",
        }
    )