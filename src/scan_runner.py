"""Orchestrates all six scan engines and collects results."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List


class Severity(Enum):
    """Finding severity levels."""

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


@dataclass
class Finding:
    """A single security finding produced by a scan engine."""

    engine: str
    title: str
    description: str
    severity: Severity
    weight: float = 1.0
    fix_command: str | None = None
    fix_description: str | None = None


@dataclass
class ScanResult:
    """Aggregated results from a full scan run."""

    findings: List[Finding] = field(default_factory=list)
    score: float = 100.0
    label: str = "Secure"


class ScanRunner:
    """Runs all scan engines and returns combined results."""

    def __init__(self) -> None:
        self._engines: list = []

    def run_all(self) -> ScanResult:
        """Execute every registered engine and return aggregated results."""
        # TODO: Implement engine orchestration
        return ScanResult()
