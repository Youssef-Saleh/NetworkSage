"""NetworkSage-X: Multi-agent SOC analyst with explainable attribution."""

from __future__ import annotations

from pathlib import Path

try:
    from dotenv import load_dotenv

    _env_path = Path(__file__).resolve().parents[2] / ".env"
    if _env_path.exists():
        load_dotenv(_env_path, override=False)
except ImportError:
    pass

__version__ = "0.1.0"