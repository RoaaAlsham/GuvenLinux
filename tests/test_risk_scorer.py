"""Tests for Risk Scoring engine."""

from src.risk_scorer import calculate_score, score_label
from src.scan_runner import Finding, Severity


class TestRiskScorer:
    """Risk scorer test cases."""

    def test_no_findings_gives_perfect_score(self) -> None:
        assert calculate_score([]) == 100.0

    def test_critical_finding_reduces_score(self) -> None:
        findings = [
            Finding(
                engine="test",
                title="Test Critical",
                description="A critical issue",
                severity=Severity.CRITICAL,
                weight=1.0,
            )
        ]
        score = calculate_score(findings)
        assert score == 90.0

    def test_score_does_not_go_below_zero(self) -> None:
        findings = [
            Finding(
                engine="test",
                title=f"Issue {i}",
                description="Critical",
                severity=Severity.CRITICAL,
                weight=5.0,
            )
            for i in range(10)
        ]
        assert calculate_score(findings) == 0.0

    def test_score_labels(self) -> None:
        assert score_label(95) == "Secure"
        assert score_label(75) == "Moderate Risk"
        assert score_label(50) == "High Risk"
        assert score_label(20) == "Critical"
