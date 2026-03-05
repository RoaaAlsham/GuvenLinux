"""Tests for Port & Network Scanner engine."""

from src.engines.port_scanner import PortScanner


class TestPortScanner:
    """Port scanner test cases."""

    def test_risky_ports_defined(self) -> None:
        scanner = PortScanner()
        assert 23 in scanner.RISKY_PORTS
        assert 21 in scanner.RISKY_PORTS

    def test_scan_returns_list(self) -> None:
        scanner = PortScanner()
        results = scanner.scan()
        assert isinstance(results, list)
