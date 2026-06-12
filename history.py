# -*- coding: utf-8 -*-
"""
Fredo — Community Edition
Local scan history (SQLite).

Every scan is persisted to ~/.fredo/history.db so results survive restarts and
can be re-opened, compared, and exported later. Schema mirrors a trimmed slice
of the full product's `scans` table.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DATA_DIR = Path.home() / ".fredo"
DB_PATH = DATA_DIR / "history.db"


def _conn() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(str(DB_PATH))
    c.row_factory = sqlite3.Row
    return c


def init_db() -> None:
    with _conn() as c:
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                target       TEXT    NOT NULL,
                engine       TEXT    NOT NULL DEFAULT 'builtin',
                protocol     TEXT    NOT NULL DEFAULT 'tcp',
                open_ports   TEXT    NOT NULL DEFAULT '[]',
                services     TEXT    NOT NULL DEFAULT '{}',
                threat_score INTEGER DEFAULT 0,
                analysis     TEXT    DEFAULT '',
                raw_output   TEXT    DEFAULT '',
                timestamp    TEXT    NOT NULL
            );
            """
        )


def save_scan(result) -> int:
    """Persist a scanner.ScanResult. Returns the new row id."""
    ts = result.timestamp or datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
    with _conn() as c:
        cur = c.execute(
            "INSERT INTO scans "
            "(target,engine,protocol,open_ports,services,threat_score,analysis,raw_output,timestamp) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (
                result.target,
                result.engine,
                "tcp",
                json.dumps(result.open_ports),
                json.dumps({str(k): v for k, v in result.services.items()}),
                result.threat_score,
                result.analysis,
                result.raw_output,
                ts,
            ),
        )
        return cur.lastrowid


def get_recent_scans(limit: int = 100) -> list[dict]:
    with _conn() as c:
        rows = c.execute(
            "SELECT id,target,engine,open_ports,threat_score,timestamp "
            "FROM scans ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        try:
            d["open_ports"] = json.loads(d["open_ports"])
        except Exception:
            d["open_ports"] = []
        out.append(d)
    return out


def get_scan(scan_id: int) -> dict | None:
    with _conn() as c:
        row = c.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not row:
        return None
    d = dict(row)
    for key in ("open_ports", "services"):
        try:
            d[key] = json.loads(d[key])
        except Exception:
            d[key] = [] if key == "open_ports" else {}
    return d


def delete_scan(scan_id: int) -> None:
    with _conn() as c:
        c.execute("DELETE FROM scans WHERE id=?", (scan_id,))


def clear_history() -> None:
    with _conn() as c:
        c.execute("DELETE FROM scans")


def get_stats() -> dict:
    with _conn() as c:
        count = c.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        last = c.execute(
            "SELECT target,threat_score,timestamp FROM scans ORDER BY id DESC LIMIT 1"
        ).fetchone()
        avg = c.execute("SELECT AVG(threat_score) FROM scans").fetchone()[0]
    return {
        "scan_count": count,
        "last_scan": dict(last) if last else None,
        "avg_score": round(avg) if avg is not None else 0,
    }
