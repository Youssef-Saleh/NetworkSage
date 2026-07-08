"""In-memory vector store for MITRE ATT&CK + CVE knowledge base."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np

from networksage.clients.hf_client import HFClient
from networksage.schemas.models import RetrievedDoc


@dataclass
class _Document:
    source: str
    doc_id: str
    title: str
    text: str


class KnowledgeBase:
    def __init__(self, hf_client: HFClient) -> None:
        self.hf_client = hf_client
        self._docs: list[_Document] = []
        self._embeddings: np.ndarray | None = None

    def add(self, source: str, doc_id: str, title: str, text: str) -> None:
        self._docs.append(_Document(source=source, doc_id=doc_id, title=title, text=text))

    def add_many(self, docs: list[dict[str, str]]) -> None:
        for d in docs:
            self.add(source=d["source"], doc_id=d["doc_id"], title=d["title"], text=d["text"])

    def size(self) -> int:
        return len(self._docs)

    def _ensure_index(self) -> None:
        if self._embeddings is None or len(self._embeddings) != len(self._docs):
            texts = [f"{d.title}\n\n{d.text}" for d in self._docs]
            if not texts:
                self._embeddings = np.zeros((0, 0), dtype=np.float32)
                return
            vectors = self.hf_client.feature_extraction(texts)
            self._embeddings = np.asarray(vectors, dtype=np.float32)

    def retrieve(self, query: str, top_k: int = 5) -> list[RetrievedDoc]:
        if not self._docs:
            return []
        self._ensure_index()
        if self._embeddings is None or self._embeddings.size == 0:
            return []
        q_vecs = self.hf_client.feature_extraction([query])
        q_vec = np.asarray(q_vecs[0], dtype=np.float32)
        doc_norms = np.linalg.norm(self._embeddings, axis=1, keepdims=True) + 1e-12
        q_norm = np.linalg.norm(q_vec) + 1e-12
        sims = (self._embeddings @ q_vec) / (doc_norms.squeeze() * q_norm)
        top_idx = np.argsort(-sims)[:top_k]
        return [
            RetrievedDoc(source=self._docs[i].source, doc_id=self._docs[i].doc_id, title=self._docs[i].title, snippet=self._docs[i].text[:300], score=float(sims[i]))
            for i in top_idx
        ]

    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"docs": [{"source": d.source, "doc_id": d.doc_id, "title": d.title, "text": d.text} for d in self._docs]}
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path, hf_client: HFClient) -> "KnowledgeBase":
        path = Path(path)
        payload = json.loads(path.read_text(encoding="utf-8"))
        kb = cls(hf_client)
        kb.add_many(payload.get("docs", []))
        return kb


SEED_MITRE_TECHNIQUES: list[dict[str, str]] = [
    {"source": "mitre-attack", "doc_id": "T1566", "title": "Phishing (T1566)", "text": "Adversaries send phishing messages to gain access to victim systems. Spearphishing involves highly targeted emails. Subtechniques include T1566.001 Spearphishing Attachment, T1566.002 Spearphishing Link."},
    {"source": "mitre-attack", "doc_id": "T1059", "title": "Command and Scripting Interpreter (T1059)", "text": "Adversaries abuse command and script interpreters to execute commands. Subtechniques include T1059.001 PowerShell, T1059.003 Windows Command Shell, T1059.006 Python."},
    {"source": "mitre-attack", "doc_id": "T1071", "title": "Application Layer Protocol (T1071)", "text": "Adversaries communicate using application layer protocols to avoid detection. Subtechniques include T1071.001 Web Protocols, T1071.004 DNS."},
    {"source": "mitre-attack", "doc_id": "T1041", "title": "Exfiltration Over C2 Channel (T1041)", "text": "Adversaries steal data by exfiltrating it over an existing command and control channel."},
    {"source": "mitre-attack", "doc_id": "T1486", "title": "Data Encrypted for Impact (T1486)", "text": "Adversaries encrypt data on target systems to interrupt availability. Common in ransomware operations."},
    {"source": "mitre-attack", "doc_id": "T1190", "title": "Exploit Public-Facing Application (T1190)", "text": "Adversaries exploit weaknesses in public-facing applications to gain initial access. Often tied to CVE-driven exploitation."},
    {"source": "mitre-attack", "doc_id": "T1078", "title": "Valid Accounts (T1078)", "text": "Adversaries obtain and abuse credentials of existing accounts. Subtechniques include T1078.001 Default Accounts, T1078.003 Local Accounts, T1078.004 Cloud Accounts."},
    {"source": "mitre-attack", "doc_id": "T1027", "title": "Obfuscated Files or Information (T1027)", "text": "Adversaries attempt to make payloads difficult to discover or analyze. Includes software packing, encryption, and embedded payloads."},
    {"source": "mitre-attack", "doc_id": "T1053", "title": "Scheduled Task/Job (T1053)", "text": "Adversaries abuse task scheduling to execute malicious code at specific times or intervals."},
    {"source": "mitre-attack", "doc_id": "T1098", "title": "Account Manipulation (T1098)", "text": "Adversaries may manipulate accounts to maintain access. Includes adding credentials, modifying permissions, and SSH key injection."},
]


def seed_default_knowledge_base(hf_client: HFClient) -> KnowledgeBase:
    kb = KnowledgeBase(hf_client)
    kb.add_many(SEED_MITRE_TECHNIQUES)
    return kb


def load_mitre_from_stix(stix_path: str | Path, hf_client: HFClient, max_techniques: int = 200) -> KnowledgeBase:
    kb = KnowledgeBase(hf_client)
    path = Path(stix_path)
    if not path.exists():
        return seed_default_knowledge_base(hf_client)
    try:
        bundle = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return seed_default_knowledge_base(hf_client)
    count = 0
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ext_refs = obj.get("external_references", [])
        tech_id = ""
        url = ""
        for ref in ext_refs:
            if ref.get("source_name") == "mitre-attack":
                tech_id = ref.get("external_id", "")
                url = ref.get("url", "")
                break
        if not tech_id:
            continue
        kb.add(source="mitre-attack", doc_id=tech_id, title=f"{tech_id} - {obj.get('name', '')}", text=f"{obj.get('description', '')}\n\nReference: {url}")
        count += 1
        if count >= max_techniques:
            break
    if kb.size() == 0:
        return seed_default_knowledge_base(hf_client)
    return kb


def maybe_fetch_mitre_stix(target_path: str | Path) -> bool:
    target = Path(target_path)
    if target.exists() and target.stat().st_size > 1_000_000:
        return True
    url = os.getenv("MITRE_STIX_URL", "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json")
    try:
        import httpx

        target.parent.mkdir(parents=True, exist_ok=True)
        resp = httpx.get(url, timeout=60.0)
        resp.raise_for_status()
        target.write_bytes(resp.content)
        return True
    except Exception:
        return False