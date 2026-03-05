"""Risk scoring and classification engine."""

from __future__ import annotations

from typing import List

from src.scan_runner import Finding, Severity

SEVERITY_MULTIPLIERS = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 5,
    Severity.MEDIUM: 2,
    Severity.LOW: 0.5,
    Severity.INFO: 0,
}

SCORE_LABELS = [
    (85, "Secure"),
    (65, "Moderate Risk"),
    (40, "High Risk"),
    (0, "Critical"),
]


def calculate_score(findings: List[Finding]) -> float:
    """Calculate the overall system risk score (0-100)."""
    penalty = sum(
        f.weight * SEVERITY_MULTIPLIERS.get(f.severity, 0) for f in findings
    )
    return max(0.0, min(100.0, 100.0 - penalty))


def score_label(score: float) -> str:
    """Return human-readable label for a given score."""
    for threshold, label in SCORE_LABELS:
        if score >= threshold:
            return label
    return "Critical"
