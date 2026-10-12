import sqlite3
import sys
from pathlib import Path
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import seed
from agent import db, sessions

@pytest.fixture(autouse=True)
def warehouse(tmp_path, monkeypatch):
    path = tmp_path / 'fixture.db'
    with sqlite3.connect(path) as conn:
        conn.executescript(seed.SCHEMA)
        for table, rows in [('users', seed.USERS), ('customers', seed.CUSTOMERS),
                            ('transactions', seed.TRANSACTIONS), ('alerts', seed.ALERTS), ('case_notes', seed.CASE_NOTES)]:
            conn.executemany(f'INSERT INTO {table} VALUES (' + ','.join('?' for _ in rows[0]) + ')', rows)
    monkeypatch.setattr(db, 'DB_PATH', str(path))
    monkeypatch.setenv('BI_AUDIT_DIR', str(tmp_path / 'audit'))
    sessions.reset()
    yield path
    sessions.reset()
