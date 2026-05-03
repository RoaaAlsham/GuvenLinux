# src/log_manager.py
"""Audit logging — records every scan run and fix applied."""
from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime
from pathlib import Path

LOG_DIR = Path.home() / ".local" / "share" / "guvenlinux"
DB_PATH = LOG_DIR / "audit.db" # operator overloading to / to act as path joiner
RECENT_SCANS_LIMIT=50

logger = logging.getLogger(__name__)


class LogManager:
    """
    Writes scan events and fix actions to a SQLite audit log.

    Two tables:
      scan_runs  — one row per scan, stores score and finding count
      fix_events — one row per applied fix, stores action and result
    """

    def __init__(self) -> None:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(DB_PATH), check_same_thread=False) 
        #check_same_thread=False because data maybe written to a thread and read from another, (in a background thread which prevent GUI from freezing)
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS scan_runs (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT NOT NULL,
                score       REAL NOT NULL,
                label       TEXT NOT NULL,
                finding_count INTEGER NOT NULL,
                findings_json TEXT
            );

            CREATE TABLE IF NOT EXISTS fix_events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT NOT NULL,
                action_id   TEXT NOT NULL,
                title       TEXT NOT NULL,
                command     TEXT NOT NULL,
                success     INTEGER NOT NULL,
                output      TEXT
            );
        """)
        self._conn.commit()

    def log_scan(self, score: float, label: str, findings: list) -> int:
        """Log a completed scan. Returns the row id."""
        findings_data = [
            {
                "engine":   f.engine,
                "title":    f.title,
                "severity": f.severity.value,
            }
            for f in findings
        ]
        cur = self._conn.execute(
            """INSERT INTO scan_runs
               (timestamp, score, label, finding_count, findings_json)
               VALUES (?, ?, ?, ?, ?)""",
            (
                datetime.now().isoformat(),
                round(score, 2),
                label,
                len(findings),
                json.dumps(findings_data),
            ),
        )
        self._conn.commit()
        logger.debug("Logged scan run id=%d score=%.1f", cur.lastrowid, score)
        return cur.lastrowid

    def log_fix(self, action_id: str, title: str,
                command: str, success: bool, output: str) -> None:
        """Log a fix attempt."""
        self._conn.execute(
            """INSERT INTO fix_events
               (timestamp, action_id, title, command, success, output)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                datetime.now().isoformat(),
                action_id, title, command,
                1 if success else 0,
                output,
            ),
        )
        self._conn.commit()
        logger.debug("Logged fix: %s success=%s", action_id, success)

    def recent_scans(self, limit: int = RECENT_SCANS_LIMIT) -> list[dict]:
        """Return most recent scan records for the Logs page."""
        cur = self._conn.execute(
            "SELECT timestamp, score, label, finding_count FROM scan_runs "
            "ORDER BY id DESC LIMIT ?", (limit,)
        )
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    def recent_fixes(self, limit: int = 100) -> list[dict]:
        """Return most recent fix records."""
        cur = self._conn.execute(
            "SELECT timestamp, title, success, output FROM fix_events "
            "ORDER BY id DESC LIMIT ?", (limit,)
        )
        cols = [d[0] for d in cur.description] #get column names by accessing the first element 
        return [dict(zip(cols, row)) for row in cur.fetchall()] 