"""Bounded, read-only warehouse access. Only the trusted compiler supplies SQL."""
from __future__ import annotations
import os
import sqlite3
import time
from contextlib import closing
from pathlib import Path

DB_PATH = os.getenv("BI_DB_PATH", str(Path(__file__).resolve().parent.parent / "fraud.db"))
MAX_ROWS = 5000
TIMEOUT_SECONDS = 2.0

class SQLError(Exception):
    pass

def connect() -> sqlite3.Connection:
    path = Path(DB_PATH).resolve()
    if not path.exists():
        raise SQLError("Warehouse unavailable. Run python seed.py first.")
    conn = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only = ON")
    deadline = time.monotonic() + TIMEOUT_SECONDS
    conn.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
    return conn

def get_user(user_id: str) -> dict:
    with closing(connect()) as conn:
        row = conn.execute("SELECT user_id, full_name, role, region FROM users WHERE user_id = ?", (user_id,)).fetchone()
    if row is None:
        raise SQLError("Unknown identity.")
    return dict(row)

def execute(sql: str, params: tuple | list = ()) -> list[dict]:
    if not sql.lstrip().upper().startswith("SELECT "):
        raise SQLError("Only compiled SELECT statements are supported.")
    with closing(connect()) as conn:
        try:
            rows = conn.execute(sql, params).fetchmany(MAX_ROWS + 1)
        except sqlite3.Error:
            raise SQLError("Query could not be completed safely.") from None
    if len(rows) > MAX_ROWS:
        raise SQLError("Result is too large; narrow the query.")
    return [dict(row) for row in rows]

def schema_text() -> str:
    return "\n\n".join(r["sql"] for r in execute(
        "SELECT sql FROM sqlite_master WHERE type='table' ORDER BY name") if r["sql"])
