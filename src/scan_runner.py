# src/scan_runner.py
"""Orchestrates all scan engines and collects results."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Type

logger = logging.getLogger(__name__)


class Severity(Enum):
    CRITICAL = "Critical"
    HIGH     = "High"
    MEDIUM   = "Medium"
    LOW      = "Low"
    INFO     = "Info"


@dataclass
class Finding:
    engine: str
    title: str
    description: str
    severity: Severity
    weight: float = 1.0
    fix_command: str | None = None
    fix_description: str | None = None


@dataclass
class ScanResult:
    findings: List[Finding] = field(default_factory=list)
    score: float = 100.0
    label: str = "Secure"


class ScanRunner:
    """
    Runs all registered scan engines.

    Engines are registered as classes — ScanRunner instantiates
    them at scan time so they are always fresh.

    How to add a new engine later:
        runner.register_engine(MyNewEngine)
    That's it.
    """

    def __init__(self) -> None:
        self._engine_classes: list[Type] = []

    def register_engine(self, engine_class: Type) -> None:
        """Register an engine class. It will be instantiated on each scan."""
        self._engine_classes.append(engine_class)
        logger.debug("Registered engine: %s", engine_class.__name__)

    def run_all(self, progress_callback=None) -> ScanResult:
        """
        Execute every registered engine and return aggregated results.

        progress_callback(engine_name: str, current: int, total: int)
            Called after each engine finishes — use it to update a
            GTK progress bar from the main thread via GLib.idle_add.
        """
        all_findings: List[Finding] = []
        total = len(self._engine_classes)

        for idx, engine_class in enumerate(self._engine_classes, start=1):
            name = engine_class.__name__
            logger.info("Running engine %d/%d: %s", idx, total, name)

            try:
                engine = engine_class()
                findings = engine.scan()
                all_findings.extend(findings)
                logger.info("%s returned %d finding(s)", name, len(findings))
            except Exception as exc:
                # One engine crashing must never abort the whole scan
                logger.error("Engine %s crashed: %s", name, exc, exc_info=True)

            if progress_callback:
                progress_callback(name, idx, total)

        from src.risk_scorer import calculate_score, score_label
        score = calculate_score(all_findings)
        label = score_label(score)

        return ScanResult(findings=all_findings, score=score, label=label)