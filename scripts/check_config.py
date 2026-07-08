"""Configuration check: print which NetworkSage-X integrations are wired.

Run: `python -m scripts.check_config`

Reads .env if present, then prints which API keys are detected and which
agents will run with real backends vs deterministic fallback.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


def _check(name: str, value: str | None, *, masked: bool = True) -> str:
    if not value:
        return f"  [ ] {name:<26} (not set)"
    if masked and len(value) > 8:
        return f"  [x] {name:<26} ({value[:4]}...{value[-4:]})"
    return f"  [x] {name:<26} {value}"


def main() -> int:
    try:
        from dotenv import load_dotenv

        env_path = Path(__file__).resolve().parents[1] / ".env"
        if env_path.exists():
            load_dotenv(env_path, override=False)
    except ImportError:
        pass

    print("NetworkSage-X configuration check")
    print("=" * 60)
    print()
    print("Model serving:")
    print(_check("HF_TOKEN", os.getenv("HF_TOKEN") or os.getenv("HUGGINGFACEHUB_API_TOKEN")))
    print(_check("NETWORKSAGE_LLM_MODEL", os.getenv("NETWORKSAGE_LLM_MODEL"), masked=False))
    print(_check("NETWORKSAGE_EMBED_MODEL", os.getenv("NETWORKSAGE_EMBED_MODEL"), masked=False))
    print(_check("NETWORKSAGE_IOC_MODEL", os.getenv("NETWORKSAGE_IOC_MODEL"), masked=False))
    print(_check("OLLAMA_BASE_URL", os.getenv("OLLAMA_BASE_URL"), masked=False))
    print()
    print("Threat intel:")
    print(_check("ABUSEIPDB_API_KEY", os.getenv("ABUSEIPDB_API_KEY")))
    print(_check("VIRUSTOTAL_API_KEY", os.getenv("VIRUSTOTAL_API_KEY")))
    print(_check("ALIENVAULT_OTX_API_KEY", os.getenv("ALIENVAULT_OTX_API_KEY")))
    print(_check("GREYNOISE_API_KEY", os.getenv("GREYNOISE_API_KEY")))
    print(_check("NVD_API_KEY", os.getenv("NVD_API_KEY")))
    print()
    print("Observability:")
    print(_check("LANGCHAIN_API_KEY", os.getenv("LANGCHAIN_API_KEY")))
    print(_check("LANGFUSE_PUBLIC_KEY", os.getenv("LANGFUSE_PUBLIC_KEY")))
    print(_check("LANGFUSE_SECRET_KEY", os.getenv("LANGFUSE_SECRET_KEY")))
    print()
    print("Database:")
    print(_check("DATABASE_URL", os.getenv("DATABASE_URL"), masked=False))
    print()

    hf_configured = bool(os.getenv("HF_TOKEN") or os.getenv("HUGGINGFACEHUB_API_TOKEN"))
    if hf_configured:
        print("Status: LLM-backed agents will use real HF Inference API.")
        print("        Run `python -m scripts.run_eval` to see boosted technique recall.")
    else:
        print("Status: running with deterministic fallback (no HF_TOKEN detected).")
        print("        Add HF_TOKEN to .env to enable real LLM-backed agent reasoning.")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())