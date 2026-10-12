"""Private audit records released rows, never withheld cell values."""
from __future__ import annotations
import json
import os
import threading
from pathlib import Path
from datetime import datetime, timezone
from .config import ROOT

_lock = threading.Lock()

def emit(record: dict) -> None:
    directory = Path(os.getenv("BI_AUDIT_DIR", str(ROOT / ".runtime")))
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = directory / "audit.jsonl"
    with _lock:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a") as stream:
            stream.write(json.dumps({"timestamp": datetime.now(timezone.utc).isoformat(), **record}, ensure_ascii=False) + "\n")
