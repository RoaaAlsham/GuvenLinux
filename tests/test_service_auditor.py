"""Tests for Service Auditor engine."""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch


from src.engines.service_auditor import ServiceAuditor, ServiceInfo
from src.scan_runner import Severity


# ── JSON fixtures ─────────────────────────────────────────────────────────────

def _make_unit(
    unit: str,
    load: str = "loaded",
    active: str = "active",
    sub: str = "running",
    description: str = "Test service",
) -> dict:
    """Helper — build a single systemctl JSON unit entry."""
    return {
        "unit": unit,
        "load": load,
        "active": active,
        "sub": sub,
        "description": description,
    }


def _make_raw(*units: dict) -> str:
    """Helper — serialize unit dicts to JSON string as systemctl would."""
    return json.dumps(list(units))


def _mock_systemctl(stdout: str, returncode: int = 0) -> MagicMock:
    """Helper — build a mock subprocess.run result."""
    mock = MagicMock()
    mock.returncode = returncode
    mock.stdout = stdout
    mock.stderr = ""
    return mock


# Common fixtures
CLEAN_VM = _make_raw(
    _make_unit("ssh.service", description="OpenBSD Secure Shell server"),
    _make_unit("cron.service", description="Regular background program"),
    _make_unit("NetworkManager.service", description="Network Manager"),
)

TELNET_ACTIVE = _make_raw(
    _make_unit("ssh.service"),
    _make_unit("telnet.service", description="Telnet Server"),
)

TELNET_INACTIVE = _make_raw(
    _make_unit(
        "telnet.service",
        load="loaded",
        active="inactive",
        sub="dead",
    ),
)

MULTIPLE_DANGEROUS = _make_raw(
    _make_unit("telnet.service"),
    _make_unit("vsftpd.service", description="FTP Server"),
    _make_unit("avahi-daemon.service", description="Avahi mDNS"),
    _make_unit("cups.service", description="CUPS Printing"),
)


# ── Structure tests ───────────────────────────────────────────────────────────

class TestServiceAuditorStructure:

    def test_dangerous_services_not_empty(self) -> None:
        assert len(ServiceAuditor.DANGEROUS_SERVICES) > 0

    def test_telnet_in_dangerous_services(self) -> None:
        assert "telnet.service" in ServiceAuditor.DANGEROUS_SERVICES

    def test_ftp_in_dangerous_services(self) -> None:
        assert "vsftpd.service" in ServiceAuditor.DANGEROUS_SERVICES

    def test_rsh_in_dangerous_services(self) -> None:
        assert "rsh.service" in ServiceAuditor.DANGEROUS_SERVICES

    def test_each_entry_has_four_fields(self) -> None:
        for name, entry in ServiceAuditor.DANGEROUS_SERVICES.items():
            assert len(entry) == 4, (
                f"{name} must have (reason, severity, weight, fix_command)"
            )

    def test_each_entry_has_positive_weight(self) -> None:
        for name, (_, _, weight, _) in ServiceAuditor.DANGEROUS_SERVICES.items():
            assert weight > 0, f"{name} has non-positive weight"

    def test_each_fix_command_contains_disable(self) -> None:
        for name, (_, _, _, fix) in ServiceAuditor.DANGEROUS_SERVICES.items():
            assert "disable" in fix, (
                f"{name} fix_command should contain 'disable'"
            )

    def test_dangerous_sockets_not_empty(self) -> None:
        assert len(ServiceAuditor.DANGEROUS_SOCKETS) > 0

    def test_telnet_socket_in_dangerous_sockets(self) -> None:
        assert "telnet.socket" in ServiceAuditor.DANGEROUS_SOCKETS


# ── parse_units tests ─────────────────────────────────────────────────────────

class TestParseUnits:

    def test_returns_list(self) -> None:
        auditor = ServiceAuditor()
        result = auditor.parse_units(CLEAN_VM)
        assert isinstance(result, list)

    def test_parses_correct_count(self) -> None:
        auditor = ServiceAuditor()
        result = auditor.parse_units(CLEAN_VM)
        assert len(result) == 3

    def test_returns_service_info_objects(self) -> None:
        auditor = ServiceAuditor()
        result = auditor.parse_units(CLEAN_VM)
        for item in result:
            assert isinstance(item, ServiceInfo)

    def test_parses_unit_name(self) -> None:
        auditor = ServiceAuditor()
        result = auditor.parse_units(CLEAN_VM)
        units = [s.unit for s in result]
        assert "ssh.service" in units

    def test_parses_active_state(self) -> None:
        auditor = ServiceAuditor()
        result = auditor.parse_units(CLEAN_VM)
        ssh = next(s for s in result if s.unit == "ssh.service")
        assert ssh.active == "active"

    def test_parses_description(self) -> None:
        auditor = ServiceAuditor()
        result = auditor.parse_units(CLEAN_VM)
        ssh = next(s for s in result if s.unit == "ssh.service")
        assert "Secure Shell" in ssh.description

    def test_empty_string_returns_empty_list(self) -> None:
        auditor = ServiceAuditor()
        result = auditor.parse_units("")
        assert result == []

    def test_invalid_json_returns_empty_list(self) -> None:
        auditor = ServiceAuditor()
        result = auditor.parse_units("not valid json {{{")
        assert result == []

    def test_missing_unit_key_skipped(self) -> None:
        """Entry without 'unit' key must be skipped, not crash."""
        raw = json.dumps([{"load": "loaded", "active": "active"}])
        auditor = ServiceAuditor()
        result = auditor.parse_units(raw)
        assert result == []

    def test_extra_fields_ignored(self) -> None:
        """Unknown fields in JSON must not cause errors."""
        raw = json.dumps([{
            "unit": "ssh.service",
            "load": "loaded",
            "active": "active",
            "sub": "running",
            "description": "SSH",
            "unexpected_field": "value",
        }])
        auditor = ServiceAuditor()
        result = auditor.parse_units(raw)
        assert len(result) == 1


# ── _is_active tests ──────────────────────────────────────────────────────────

class TestIsActive:

    def test_loaded_and_active_is_true(self) -> None:
        auditor = ServiceAuditor()
        service = ServiceInfo("x.service", "loaded", "active", "running", "X")
        assert auditor._is_active(service) is True

    def test_inactive_service_is_false(self) -> None:
        auditor = ServiceAuditor()
        service = ServiceInfo("x.service", "loaded", "inactive", "dead", "X")
        assert auditor._is_active(service) is False

    def test_not_found_service_is_false(self) -> None:
        auditor = ServiceAuditor()
        service = ServiceInfo("x.service", "not-found", "inactive", "dead", "X")
        assert auditor._is_active(service) is False

    def test_exited_service_is_active(self) -> None:
        """sub=exited with active=active means service ran and completed."""
        auditor = ServiceAuditor()
        service = ServiceInfo("x.service", "loaded", "active", "exited", "X")
        assert auditor._is_active(service) is True


# ── scan() tests ──────────────────────────────────────────────────────────────

class TestScan:

    def test_scan_returns_list(self) -> None:
        auditor = ServiceAuditor()
        with patch("subprocess.run", return_value=_mock_systemctl(CLEAN_VM)):
            result = auditor.scan()
        assert isinstance(result, list)

    def test_clean_vm_produces_no_findings(self) -> None:
        auditor = ServiceAuditor()
        with patch("subprocess.run", return_value=_mock_systemctl(CLEAN_VM)):
            findings = auditor.scan()
        assert findings == []

    def test_active_telnet_produces_critical_finding(self) -> None:
        auditor = ServiceAuditor()
        with patch("subprocess.run", return_value=_mock_systemctl(TELNET_ACTIVE)):
            findings = auditor.scan()
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_inactive_telnet_produces_no_finding(self) -> None:
        """Dangerous service installed but not running — must not be flagged."""
        auditor = ServiceAuditor()
        with patch("subprocess.run", return_value=_mock_systemctl(TELNET_INACTIVE)):
            findings = auditor.scan()
        assert findings == []

    def test_multiple_dangerous_services_all_flagged(self) -> None:
        auditor = ServiceAuditor()
        with patch("subprocess.run", return_value=_mock_systemctl(MULTIPLE_DANGEROUS)):
            findings = auditor.scan()
        assert len(findings) == 4

    def test_finding_title_contains_service_name(self) -> None:
        auditor = ServiceAuditor()
        with patch("subprocess.run", return_value=_mock_systemctl(TELNET_ACTIVE)):
            findings = auditor.scan()
        assert "telnet.service" in findings[0].title

    def test_finding_engine_name(self) -> None:
        auditor = ServiceAuditor()
        with patch("subprocess.run", return_value=_mock_systemctl(TELNET_ACTIVE)):
            findings = auditor.scan()
        assert findings[0].engine == "service_auditor"

    def test_finding_has_fix_command(self) -> None:
        auditor = ServiceAuditor()
        with patch("subprocess.run", return_value=_mock_systemctl(TELNET_ACTIVE)):
            findings = auditor.scan()
        assert findings[0].fix_command is not None
        assert "disable" in findings[0].fix_command

    def test_finding_has_positive_weight(self) -> None:
        auditor = ServiceAuditor()
        with patch("subprocess.run", return_value=_mock_systemctl(TELNET_ACTIVE)):
            findings = auditor.scan()
        assert findings[0].weight > 0

    def test_systemctl_failure_returns_empty(self) -> None:
        auditor = ServiceAuditor()
        with patch("subprocess.run", return_value=_mock_systemctl("", returncode=1)):
            findings = auditor.scan()
        assert findings == []

    def test_systemctl_not_found_returns_empty(self) -> None:
        auditor = ServiceAuditor()
        with patch("subprocess.run", side_effect=FileNotFoundError):
            findings = auditor.scan()
        assert findings == []

    def test_systemctl_timeout_returns_empty(self) -> None:
        import subprocess as sp
        auditor = ServiceAuditor()
        with patch("subprocess.run", side_effect=sp.TimeoutExpired("systemctl", 15)):
            findings = auditor.scan()
        assert findings == []

    def test_unknown_service_not_flagged(self) -> None:
        """Services not in DANGEROUS_SERVICES must never produce findings."""
        raw = _make_raw(
            _make_unit("my-custom-app.service"),
            _make_unit("some-monitoring-agent.service"),
        )
        auditor = ServiceAuditor()
        with patch("subprocess.run", return_value=_mock_systemctl(raw)):
            findings = auditor.scan()
        assert findings == []
