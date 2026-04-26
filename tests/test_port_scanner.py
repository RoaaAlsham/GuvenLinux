"""Tests for Port & Network Scanner engine."""
from __future__ import annotations

from unittest.mock import MagicMock, patch
import subprocess

import pytest

from src.engines.port_scanner import OpenPort, PortScanner
from src.scan_runner import Severity


# ── Realistic ss output fixtures ─────────────────────────────────────────────

SS_OUTPUT_CLEAN = """\
Netid  State   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port  Process
tcp    LISTEN  0       128     0.0.0.0:22           0.0.0.0:*
tcp    LISTEN  0       128     [::]:22              [::]:*
"""

SS_OUTPUT_RISKY = """\
Netid  State   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port  Process
tcp    LISTEN  0       128     0.0.0.0:22           0.0.0.0:*
tcp    LISTEN  0       128     0.0.0.0:23           0.0.0.0:*
tcp    LISTEN  0       128     0.0.0.0:21           0.0.0.0:*
tcp    LISTEN  0       128     0.0.0.0:3389         0.0.0.0:*
tcp    LISTEN  0       128     0.0.0.0:5900         0.0.0.0:*
"""

SS_OUTPUT_WITH_PROCESS = (
    "Netid  State   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port"
    "  Process\n"
    "tcp    LISTEN  0       128     0.0.0.0:23           0.0.0.0:*"
    "          users:((\"telnetd\",pid=999,fd=3))\n"
)

SS_OUTPUT_LOCALHOST_ONLY = """\
Netid  State   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port  Process
tcp    LISTEN  0       128     127.0.0.1:3306       0.0.0.0:*
tcp    LISTEN  0       128     127.0.0.1:6379       0.0.0.0:*
"""

SS_OUTPUT_IPV6_RISKY = """\
Netid  State   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port  Process
tcp    LISTEN  0       128     [::]:23              [::]:*
"""

SS_OUTPUT_EMPTY = """\
Netid  State   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port  Process
"""


def _mock_ss(stdout: str, returncode: int = 0) -> MagicMock:
    """Helper — build a mock subprocess.run result."""
    mock = MagicMock()
    mock.returncode = returncode
    mock.stdout = stdout
    mock.stderr = ""
    return mock


# ── Structure tests ───────────────────────────────────────────────────────────

class TestPortScannerStructure:

    def test_risky_ports_contains_telnet(self) -> None:
        assert 23 in PortScanner.RISKY_PORTS

    def test_risky_ports_contains_ftp(self) -> None:
        assert 21 in PortScanner.RISKY_PORTS

    def test_risky_ports_contains_rdp(self) -> None:
        assert 3389 in PortScanner.RISKY_PORTS

    def test_risky_ports_contains_vnc(self) -> None:
        assert 5900 in PortScanner.RISKY_PORTS

    def test_each_risky_port_has_four_fields(self) -> None:
        for port, entry in PortScanner.RISKY_PORTS.items():
            assert len(entry) == 4, (
                f"Port {port} entry must have (name, severity, weight, description)"
            )

    def test_each_risky_port_has_positive_weight_or_zero(self) -> None:
        for port, (_, _, weight, _) in PortScanner.RISKY_PORTS.items():
            assert weight >= 0, f"Port {port} has negative weight"

    def test_ssh_is_info_severity(self) -> None:
        """SSH must never produce a finding — it should be INFO."""
        _, severity, _, _ = PortScanner.RISKY_PORTS[22]
        assert severity == Severity.INFO

    def test_exposed_addresses_contains_ipv4_wildcard(self) -> None:
        assert "0.0.0.0" in PortScanner.EXPOSED_ADDRESSES

    def test_exposed_addresses_contains_ipv6_wildcard(self) -> None:
        assert "::" in PortScanner.EXPOSED_ADDRESSES


# ── _parse_port tests ─────────────────────────────────────────────────────────

class TestParsePort:

    def test_parses_ipv4(self) -> None:
        scanner = PortScanner()
        address, port = scanner._parse_port("0.0.0.0:22")
        assert address == "0.0.0.0"
        assert port == 22

    def test_parses_ipv6(self) -> None:
        scanner = PortScanner()
        address, port = scanner._parse_port("[::]:22")
        assert address == "::"
        assert port == 22

    def test_parses_localhost(self) -> None:
        scanner = PortScanner()
        address, port = scanner._parse_port("127.0.0.1:3306")
        assert address == "127.0.0.1"
        assert port == 3306

    def test_parses_high_port_number(self) -> None:
        scanner = PortScanner()
        _, port = scanner._parse_port("0.0.0.0:65535")
        assert port == 65535

    def test_invalid_format_raises(self) -> None:
        scanner = PortScanner()
        with pytest.raises((ValueError, IndexError)):
            scanner._parse_port("notavalidaddress")


# ── _parse_process tests ──────────────────────────────────────────────────────

class TestParseProcess:

    def test_extracts_process_name(self) -> None:
        scanner = PortScanner()
        result = scanner._parse_process('users:(("sshd",pid=123,fd=4))')
        assert result == "sshd"

    def test_empty_string_returns_none(self) -> None:
        scanner = PortScanner()
        assert scanner._parse_process("") is None

    def test_dash_returns_none(self) -> None:
        scanner = PortScanner()
        assert scanner._parse_process("-") is None

    def test_extracts_telnetd(self) -> None:
        scanner = PortScanner()
        result = scanner._parse_process('users:(("telnetd",pid=999,fd=3))')
        assert result == "telnetd"


# ── parse_ss_output tests ─────────────────────────────────────────────────────

class TestParseSsOutput:

    def test_returns_list(self) -> None:
        scanner = PortScanner()
        result = scanner.parse_ss_output(SS_OUTPUT_CLEAN)
        assert isinstance(result, list)

    def test_parses_two_ssh_ports(self) -> None:
        scanner = PortScanner()
        result = scanner.parse_ss_output(SS_OUTPUT_CLEAN)
        assert len(result) == 2

    def test_skips_header_line(self) -> None:
        scanner = PortScanner()
        result = scanner.parse_ss_output(SS_OUTPUT_CLEAN)
        # Header line must not appear as an OpenPort
        for port in result:
            assert isinstance(port.port, int)

    def test_parses_protocol_correctly(self) -> None:
        scanner = PortScanner()
        result = scanner.parse_ss_output(SS_OUTPUT_CLEAN)
        assert all(p.protocol == "tcp" for p in result)

    def test_parses_ipv4_address(self) -> None:
        scanner = PortScanner()
        result = scanner.parse_ss_output(SS_OUTPUT_CLEAN)
        addresses = [p.local_address for p in result]
        assert "0.0.0.0" in addresses

    def test_parses_ipv6_address(self) -> None:
        scanner = PortScanner()
        result = scanner.parse_ss_output(SS_OUTPUT_CLEAN)
        addresses = [p.local_address for p in result]
        assert "::" in addresses

    def test_empty_output_returns_empty_list(self) -> None:
        scanner = PortScanner()
        result = scanner.parse_ss_output(SS_OUTPUT_EMPTY)
        assert result == []

    def test_parses_process_name(self) -> None:
        scanner = PortScanner()
        result = scanner.parse_ss_output(SS_OUTPUT_WITH_PROCESS)
        assert len(result) == 1
        assert result[0].process == "telnetd"

    def test_returns_openport_objects(self) -> None:
        scanner = PortScanner()
        result = scanner.parse_ss_output(SS_OUTPUT_CLEAN)
        for item in result:
            assert isinstance(item, OpenPort)


# ── scan() integration tests ──────────────────────────────────────────────────

class TestScan:

    def test_scan_returns_list(self) -> None:
        scanner = PortScanner()
        with patch("subprocess.run", return_value=_mock_ss(SS_OUTPUT_CLEAN)):
            result = scanner.scan()
        assert isinstance(result, list)

    def test_clean_vm_produces_no_findings(self) -> None:
        """SSH only — should produce zero findings."""
        scanner = PortScanner()
        with patch("subprocess.run", return_value=_mock_ss(SS_OUTPUT_CLEAN)):
            findings = scanner.scan()
        assert findings == []

    def test_telnet_port_produces_critical_finding(self) -> None:
        scanner = PortScanner()
        with patch("subprocess.run", return_value=_mock_ss(SS_OUTPUT_WITH_PROCESS)):
            findings = scanner.scan()
        assert any(f.severity == Severity.CRITICAL for f in findings)
        assert any("23" in f.title for f in findings)

    def test_risky_ports_all_flagged(self) -> None:
        """FTP, Telnet, RDP, VNC all open — all should produce findings."""
        scanner = PortScanner()
        with patch("subprocess.run", return_value=_mock_ss(SS_OUTPUT_RISKY)):
            findings = scanner.scan()
        assert len(findings) >= 4  # 23, 21, 3389, 5900 (not 22)

    def test_localhost_only_ports_not_flagged(self) -> None:
        """MySQL and Redis on 127.0.0.1 — must NOT produce findings."""
        scanner = PortScanner()
        with patch("subprocess.run", return_value=_mock_ss(SS_OUTPUT_LOCALHOST_ONLY)):
            findings = scanner.scan()
        assert findings == []

    def test_ipv6_risky_port_is_flagged(self) -> None:
        """Telnet on [::] — exposed on all IPv6 interfaces, must be flagged."""
        scanner = PortScanner()
        with patch("subprocess.run", return_value=_mock_ss(SS_OUTPUT_IPV6_RISKY)):
            findings = scanner.scan()
        assert len(findings) >= 1
        assert any("23" in f.title for f in findings)

    def test_findings_have_engine_name(self) -> None:
        scanner = PortScanner()
        with patch("subprocess.run", return_value=_mock_ss(SS_OUTPUT_RISKY)):
            findings = scanner.scan()
        for f in findings:
            assert f.engine == "port_scanner"

    def test_findings_have_positive_weight(self) -> None:
        scanner = PortScanner()
        with patch("subprocess.run", return_value=_mock_ss(SS_OUTPUT_RISKY)):
            findings = scanner.scan()
        for f in findings:
            assert f.weight > 0

    def test_findings_have_fix_command(self) -> None:
        scanner = PortScanner()
        with patch("subprocess.run", return_value=_mock_ss(SS_OUTPUT_WITH_PROCESS)):
            findings = scanner.scan()
        for f in findings:
            assert f.fix_command is not None
            assert "nft" in f.fix_command

    def test_ss_failure_returns_empty_list(self) -> None:
        """If ss fails, scan must return [] not crash."""
        scanner = PortScanner()
        with patch("subprocess.run", return_value=_mock_ss("", returncode=1)):
            findings = scanner.scan()
        assert findings == []

    def test_ss_not_found_returns_empty_list(self) -> None:
        """If ss binary missing, scan must return [] not crash."""
        scanner = PortScanner()
        with patch("subprocess.run", side_effect=FileNotFoundError):
            findings = scanner.scan()
        assert findings == []

    def test_ss_timeout_returns_empty_list(self) -> None:
        """If ss times out, scan must return [] not crash."""
        scanner = PortScanner()
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("ss", 10)):
            findings = scanner.scan()
        assert findings == []


# ── Coverage gap tests ────────────────────────────────────────────────────────

class TestCoverageGaps:

    def test_parse_process_malformed_no_quotes_returns_none(self) -> None:
        """Process field exists but has no quotes — ValueError path."""
        scanner = PortScanner()
        result = scanner._parse_process("users:((sshd,pid=123,fd=4))")
        assert result is None

    def test_parse_ss_output_skips_short_lines(self) -> None:
        """Lines with fewer than 6 columns must be skipped, not crash."""
        raw = "Netid  State  Recv-Q  Send-Q  Local Address:Port  Peer Address:Port\ntcp\n"
        scanner = PortScanner()
        result = scanner.parse_ss_output(raw)
        assert result == []

    def test_parse_ss_output_skips_non_tcp_udp(self) -> None:
        """Unix socket lines (netid=unix) must be ignored."""
        raw = (
            "Netid  State   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port\n"
            "unix   LISTEN  0       0       /run/dbus.sock       *\n"
        )
        scanner = PortScanner()
        result = scanner.parse_ss_output(raw)
        assert result == []

    def test_parse_ss_output_skips_unparseable_address(self) -> None:
        """Malformed address:port column must be skipped, not crash."""
        raw = (
            "Netid  State   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port\n"
            "tcp    LISTEN  0       128     INVALID              0.0.0.0:*\n"
        )
        scanner = PortScanner()
        result = scanner.parse_ss_output(raw)
        assert result == []

    def test_non_risky_port_produces_no_finding(self) -> None:
        """A port not in RISKY_PORTS (e.g. 8888) must not produce a finding."""
        raw = (
            "Netid  State   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port\n"
            "tcp    LISTEN  0       128     0.0.0.0:8888         0.0.0.0:*\n"
        )
        scanner = PortScanner()
        with patch("subprocess.run", return_value=_mock_ss(raw)):
            findings = scanner.scan()
        assert findings == []
