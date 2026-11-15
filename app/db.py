"""SQLite history store for LINKBREAK (optional local history).

Uses only the standard library. The database file is created on first
use; nothing is ever sent anywhere.
"""

from __future__ import annotations

import os
import sqlite3
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS resolutions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    original_url TEXT NOT NULL,
    detected_provider TEXT,
    final_url TEXT,
    http_status INTEGER,
    resolution_status TEXT,
    error_message TEXT,
    elapsed_ms INTEGER,
    created_at REAL NOT NULL
);
"""


def _connect(path: str) -> sqlite3.Connection:
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(path: str) -> None:
    with _connect(path) as conn:
        conn.executescript(SCHEMA)


def save_result(path: str, result: dict) -> int:
    """Insert one resolution; returns its row id."""
    init_db(path)
    with _connect(path) as conn:
        cursor = conn.execute(
            """
            INSERT INTO resolutions
                (original_url, detected_provider, final_url, http_status,
                 resolution_status, error_message, elapsed_ms, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result.get("original_url"),
                result.get("detected_provider"),
                result.get("final_url"),
                result.get("http_status"),
                result.get("resolution_status"),
                result.get("error_message"),
                result.get("elapsed_ms"),
                time.time(),
            ),
        )
        return cursor.lastrowid


def list_history(path: str, limit: int = 50) -> list[dict]:
    """Latest resolutions, newest first."""
    if not os.path.exists(path):
        return []
    with _connect(path) as conn:
        rows = conn.execute(
            """
            SELECT id, original_url, detected_provider, final_url,
                   http_status, resolution_status, error_message,
                   elapsed_ms, created_at
            FROM resolutions
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def clear_history(path: str) -> int:
    """Delete all stored resolutions; returns the number removed."""
    if not os.path.exists(path):
        return 0
    with _connect(path) as conn:
        cursor = conn.execute("DELETE FROM resolutions")
        return cursor.rowcount
