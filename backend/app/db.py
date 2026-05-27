"""SQLite schema and path for ObservaShield MVP."""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path


def default_db_path() -> str:
    env = os.environ.get("OBSERVASHIELD_DB")
    if env:
        return env
    root = Path(__file__).resolve().parent.parent.parent
    return str(root / "data" / "observashield.db")


def connect(db_path: str) -> sqlite3.Connection:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS telemetry (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            payload TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            payload TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS incident_meta (
            incident_id TEXT PRIMARY KEY,
            correlation_key TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL DEFAULT 'open',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        """
    )
    conn.commit()
