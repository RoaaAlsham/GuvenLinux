"""Audit logging for all scans and fix actions."""

from __future__ import annotations

import logging
from pathlib import Path

LOG_DIR = Path.home() / ".local" / "share" / "pardusguard" / "logs"


class LogManager:
    """Append-only audit logger for scans and remediations."""

    def __init__(self) -> None:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        self._logger = logging.getLogger("pardusguard.audit")
        handler = logging.FileHandler(LOG_DIR / "audit.log")
        handler.setFormatter(
            logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
        )
        self._logger.addHandler(handler)
        self._logger.setLevel(logging.INFO)

    def log_scan(self, engine: str, finding_count: int) -> None:
        """Record that a scan was performed."""
        self._logger.info("SCAN engine=%s findings=%d", engine, finding_count)

    def log_fix(self, action_id: str, success: bool) -> None:
        """Record that a fix action was attempted."""
        status = "SUCCESS" if success else "FAILED"
        self._logger.info("FIX action=%s status=%s", action_id, status)
