"""
Lightweight scan history - lets the web UI show a dashboard of past scans
and trend charts (risk score over time for a given target).
"""
from __future__ import annotations
import sqlite3
from pathlib import Path
from datetime import datetime, timezone

DB_PATH = Path(__file__).parent.parent / "scan_history.db"


def _get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            overall_rating TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            critical_count INTEGER, high_count INTEGER,
            medium_count INTEGER, low_count INTEGER,
            scanned_at TEXT NOT NULL
        )
    """)
    return conn


def save_scan(url: str, risk_summary) -> None:
    conn = _get_conn()
    with conn:
        conn.execute(
            """INSERT INTO scans (url, overall_rating, risk_score, critical_count,
               high_count, medium_count, low_count, scanned_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                url,
                risk_summary.overall_rating,
                risk_summary.score,
                _count_for(risk_summary, "CRITICAL"),
                _count_for(risk_summary, "HIGH"),
                _count_for(risk_summary, "MEDIUM"),
                _count_for(risk_summary, "LOW"),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
    conn.close()


def _count_for(risk_summary, severity_name: str) -> int:
    from core.plugin_base import Severity
    return risk_summary.counts.get(Severity(severity_name), 0)


def get_history(url: str | None = None, limit: int = 50) -> list[dict]:
    conn = _get_conn()
    conn.row_factory = sqlite3.Row
    if url:
        rows = conn.execute(
            "SELECT * FROM scans WHERE url = ? ORDER BY scanned_at DESC LIMIT ?", (url, limit)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY scanned_at DESC LIMIT ?", (limit,)
        ).fetchall()
    conn.close()
    return [dict(row) for row in rows]
