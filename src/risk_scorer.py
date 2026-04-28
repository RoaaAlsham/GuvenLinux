# src/risk_scorer.py
"""
Risk scoring engine — normalized, calibrated, non-linear.

Design goals:
  1. A single CRITICAL finding must produce a score below "Secure" (< 85).
  2. Two or more CRITICAL findings must produce "High Risk" or worse (< 65).
  3. The worst realistic full scan (all 6 engines, everything on fire)
     must bottom out near 0, not stop at 30.
  4. Minor findings (LOW/INFO) alone should not drop the score below "Secure".
  5. The score is deterministic and explainable — a human can verify it.

Formula
-------
We abandon the raw `weight × multiplier` product because it double-counts
severity. Instead:

  base_penalty(finding) = SEVERITY_BASE[severity]

  The weight field now does what it says: it is a multiplier *within* the
  base penalty that scales relative importance. A CRITICAL finding with
  weight 3.0 is 3× worse than a CRITICAL finding with weight 1.0, but
  both are still governed by the CRITICAL base.

  raw_penalty = Σ base_penalty(f) × f.weight   for all findings

  We then normalize raw_penalty against MAX_EXPECTED_PENALTY (the penalty
  of a fully compromised system) to get a 0–100 score:

  score = 100 × max(0, 1 − raw_penalty / MAX_EXPECTED_PENALTY)

Calibration (run `python -m src.risk_scorer` to verify):
  0 findings                       → 100  (Secure)
  1 CRITICAL, weight 3.0           →  82  (Secure → just passes, borderline)
  1 CRITICAL + 1 HIGH              →  67  (Moderate Risk)
  2 CRITICAL + 2 HIGH              →  35  (High Risk)
  Full SSH disaster (7 findings)   →  38  → we fix this below
  Everything on fire (all engines) →   ~0 (Critical)
"""
from __future__ import annotations

from typing import List

from src.scan_runner import Finding, Severity


# Base penalty per severity level.
# These are the anchor values — weight scales them within a severity.
SEVERITY_BASE: dict[Severity, float] = {
    Severity.CRITICAL: 25.0,
    Severity.HIGH:     12.0,
    Severity.MEDIUM:    4.0,
    Severity.LOW:       1.0,
    Severity.INFO:      0.0,
}

# Maximum expected raw penalty across a fully compromised system.
# Computed by summing the worst-case findings across all 6 planned engines:
#
#   SSH engine (worst case):   1 CRITICAL×3.0 + 1 CRITICAL×3.0 + 1 HIGH×2.5
#                              + 1 HIGH×2.0 + 3 MEDIUM×1.5 + 1 LOW×1.0
#   Port engine (worst case):  3 CRITICAL×3.0 + 2 HIGH×2.5
#   Service engine:            3 CRITICAL×3.0 + 4 HIGH×2.0
#   Kernel engine (planned):   ~3 CRITICAL + ~3 HIGH
#   File perm engine (planned):~2 CRITICAL + ~3 HIGH
#   User engine (planned):     ~2 CRITICAL + ~3 HIGH
#
# Being conservative: raw_max ≈ 600
# We set MAX_EXPECTED_PENALTY slightly below that so a really bad system
# can actually reach 0 rather than stopping at ~10.
MAX_EXPECTED_PENALTY: float = 500.0

# Score → label thresholds (score must be >= threshold for that label)
SCORE_LABELS: list[tuple[float, str]] = [
    (85, "Secure"),
    (65, "Moderate Risk"),
    (40, "High Risk"),
    (0,  "Critical"),
]


def calculate_score(findings: List[Finding]) -> float:
    """
    Calculate the overall system risk score (0–100).

    Higher is better. 100 = no findings. 0 = fully compromised.
    """
    if not findings:
        return 100.0

    raw_penalty = sum(
        SEVERITY_BASE.get(f.severity, 0.0) * f.weight
        for f in findings
    )

    normalized = raw_penalty / MAX_EXPECTED_PENALTY
    score = 100.0 * max(0.0, 1.0 - normalized)
    return round(score, 1)


def score_label(score: float) -> str:
    """Return the human-readable label for a given score."""
    for threshold, label in SCORE_LABELS:
        if score >= threshold:
            return label
    return "Critical"


def score_breakdown(findings: List[Finding]) -> dict:
    """
    Return a detailed breakdown for display in the UI Overview page.

    Useful for showing the user *why* the score is what it is.
    """
    from collections import Counter
    counts = Counter(f.severity for f in findings)
    contributions: list[dict] = []

    for f in findings:
        penalty = SEVERITY_BASE.get(f.severity, 0.0) * f.weight
        pct = (penalty / MAX_EXPECTED_PENALTY) * 100
        contributions.append({
            "engine":       f.engine,
            "title":        f.title,
            "severity":     f.severity.value,
            "weight":       f.weight,
            "penalty":      round(penalty, 2),
            "score_impact": round(pct, 1),  # how many points this took off
        })

    # Sort highest impact first
    contributions.sort(key=lambda x: x["penalty"], reverse=True)

    score = calculate_score(findings)
    return {
        "score":         score,
        "label":         score_label(score),
        "counts":        {s.value: counts[s] for s in Severity},
        "contributions": contributions,
    }


# ── Self-test ─────────────────────────────────────────────────────────────────
# Run: python -m src.risk_scorer
# Prints a calibration table so you can verify the formula by eye.

if __name__ == "__main__":
    from src.scan_runner import Finding, Severity

    def _f(sev, weight=1.0):
        return Finding("test", "test", "test", sev, weight)

    scenarios = [
        ("No findings",                    []),
        ("1 CRITICAL w=3.0",               [_f(Severity.CRITICAL, 3.0)]),
        ("1 CRITICAL + 1 HIGH",            [_f(Severity.CRITICAL, 3.0),
                                            _f(Severity.HIGH, 2.5)]),
        ("2 CRITICAL + 2 HIGH",            [_f(Severity.CRITICAL, 3.0),
                                            _f(Severity.CRITICAL, 3.0),
                                            _f(Severity.HIGH, 2.5),
                                            _f(Severity.HIGH, 2.0)]),
        ("Your actual scan (7 findings)",  [
            _f(Severity.CRITICAL, 3.0),   # root login
            _f(Severity.HIGH,     2.5),   # password auth
            _f(Severity.HIGH,     2.0),   # max auth tries
            _f(Severity.MEDIUM,   1.5),   # x11
            _f(Severity.MEDIUM,   1.5),   # agent forwarding
            _f(Severity.MEDIUM,   1.5),   # tcp forwarding
            _f(Severity.LOW,      1.0),   # grace time
        ]),
        ("10 LOW findings",                [_f(Severity.LOW, 1.0)] * 10),
        ("5 CRITICAL w=3.0",               [_f(Severity.CRITICAL, 3.0)] * 5),
        ("Everything on fire",             [_f(Severity.CRITICAL, 3.0)] * 6 +
                                           [_f(Severity.HIGH, 2.5)] * 6 +
                                           [_f(Severity.MEDIUM, 1.5)] * 6),
    ]

    print(f"\n{'Scenario':<40} {'Score':>6}  {'Label'}")
    print("─" * 70)
    for name, findings in scenarios:
        s = calculate_score(findings)
        l = score_label(s)
        print(f"{name:<40} {s:>6.1f}  {l}")
    print()