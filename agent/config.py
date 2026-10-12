"""Server-only configuration; never include credentials in responses or traces."""
from __future__ import annotations
import os
from pathlib import Path
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent

def load_config() -> None:
    path = ROOT / ".env"
    if path.exists():
        content = path.read_text().strip()
        if content.startswith("sk-") and "\n" not in content:
            os.environ.setdefault("OPENAI_API_KEY", content)
        else:
            load_dotenv(path, override=False)

load_config()
MODEL = os.getenv("BI_MODEL", "gpt-5.5")
PRICING = {"gpt-5.5": (5.0, 0.5, 30.0)}
PRICING_DATE = "2026-10-10"

def estimated_cost(input_tokens: int, cached_tokens: int, output_tokens: int) -> float | None:
    rates = PRICING.get(MODEL)
    if not rates:
        return None
    return round(((input_tokens - cached_tokens) * rates[0] + cached_tokens * rates[1]
                  + output_tokens * rates[2]) / 1_000_000, 6)
