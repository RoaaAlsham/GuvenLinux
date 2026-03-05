"""Tests for Report Renderer."""

import json
from pathlib import Path

from src.report_renderer import ReportRenderer
from src.scan_runner import ScanResult


class TestReportRenderer:
    """Report renderer test cases."""

    def test_json_export_creates_file(self, tmp_path: Path) -> None:
        renderer = ReportRenderer()
        result = ScanResult(score=85.0, label="Secure")
        output = tmp_path / "report.json"
        renderer.export_json(result, output)
        assert output.exists()

    def test_json_export_valid_json(self, tmp_path: Path) -> None:
        renderer = ReportRenderer()
        result = ScanResult(score=72.0, label="Moderate Risk")
        output = tmp_path / "report.json"
        renderer.export_json(result, output)
        data = json.loads(output.read_text())
        assert data["score"] == 72.0
        assert data["label"] == "Moderate Risk"
