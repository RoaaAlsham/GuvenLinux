"""Tests for SSH Configuration Auditor engine."""
from __future__ import annotations
import tempfile
import os
from unittest.mock import patch
from src.engines.ssh_auditor import SSHAuditor
from src.scan_runner import Severity


class TestSSHAuditorDefaults:
    """Test class structure and constants."""

    def test_secure_defaults_defined(self) -> None:
        auditor = SSHAuditor()
        assert "PermitRootLogin" in auditor.SECURE_DEFAULTS
        assert auditor.SECURE_DEFAULTS["PermitRootLogin"] == "no"

    def test_all_checks_have_required_fields(self) -> None:
        auditor = SSHAuditor()
        required = {"key", "severity", "title", "description",
                    "fix_command", "fix_description", "weight"}
        for check in auditor.CHECKS:
            missing = required - check.keys()
            assert not missing, f"Check '{check.get('key')}' missing: {missing}"

    def test_protocol_check_exists(self) -> None:
        auditor = SSHAuditor()
        keys = [c["key"] for c in auditor.CHECKS]
        assert "protocol" in keys

    def test_all_check_keys_in_secure_defaults(self) -> None:
        """Every check key must have a corresponding SECURE_DEFAULTS entry."""
        auditor = SSHAuditor()
        secure_keys_lower = {k.lower() for k in auditor.SECURE_DEFAULTS}
        for check in auditor.CHECKS:
            assert check["key"] in secure_keys_lower, (
                f"Check key '{check['key']}' has no entry in SECURE_DEFAULTS"
            )


class TestParseConfig:
    """Test sshd_config file parsing."""

    def _write_config(self, content: str) -> str:
        """Helper — write content to a temp file and return its path."""
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".conf", delete=False
        )
        tmp.write(content)
        tmp.close()
        return tmp.name

    def test_parses_active_settings(self) -> None:
        path = self._write_config("PermitRootLogin yes\nX11Forwarding no\n")
        auditor = SSHAuditor()
        config = auditor.parse_config(path)
        assert config["permitrootlogin"] == "yes"
        assert config["x11forwarding"] == "no"
        os.unlink(path)

    def test_ignores_commented_lines(self) -> None:
        path = self._write_config("# PermitRootLogin yes\nX11Forwarding no\n")
        auditor = SSHAuditor()
        config = auditor.parse_config(path)
        assert "permitrootlogin" not in config
        os.unlink(path)

    def test_ignores_blank_lines(self) -> None:
        path = self._write_config("\n\nX11Forwarding no\n\n")
        auditor = SSHAuditor()
        config = auditor.parse_config(path)
        assert len(config) == 1
        os.unlink(path)

    def test_keys_are_lowercased(self) -> None:
        path = self._write_config("PERMITROOTLOGIN yes\n")
        auditor = SSHAuditor()
        config = auditor.parse_config(path)
        assert "permitrootlogin" in config
        assert "PERMITROOTLOGIN" not in config
        os.unlink(path)

    def test_values_are_lowercased(self) -> None:
        path = self._write_config("PermitRootLogin YES\n")
        auditor = SSHAuditor()
        config = auditor.parse_config(path)
        assert config["permitrootlogin"] == "yes"
        os.unlink(path)

    def test_missing_file_returns_empty_dict(self) -> None:
        auditor = SSHAuditor()
        config = auditor.parse_config("/nonexistent/path/sshd_config")
        assert config == {}

    def test_permission_error_returns_empty_dict(self) -> None:
        auditor = SSHAuditor()
        with patch("builtins.open", side_effect=PermissionError):
            config = auditor.parse_config("/etc/ssh/sshd_config")
        assert config == {}


class TestScanFindings:
    """Test that scan() produces correct findings for each parameter."""

    def _scan_with_config(self, content: str):
        """Helper — write config to temp file, run scan against it."""
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".conf", delete=False
        )
        tmp.write(content)
        tmp.close()
        auditor = SSHAuditor()
        auditor.SSHD_CONFIG_PATH = tmp.name
        findings = auditor.scan()
        os.unlink(tmp.name)
        return findings

    def test_scan_returns_list(self) -> None:
        auditor = SSHAuditor()
        assert isinstance(auditor.scan(), list)
    

    def test_no_findings_on_fully_hardened_config(self) -> None:
        config = (
            "PermitRootLogin no\n"
            "PasswordAuthentication no\n"
            "PermitEmptyPasswords no\n"
            "MaxAuthTries 3\n"
            "Protocol 2\n"
            "X11Forwarding no\n"
            "AllowAgentForwarding no\n"
            "AllowTcpForwarding no\n"
            "LoginGraceTime 60\n"
        )
        findings = self._scan_with_config(config)
        assert findings == [], (
            f"Expected no findings but got: {[f.title for f in findings]}"
        )

    def test_permit_root_login_yes_is_critical(self) -> None:
        findings = self._scan_with_config("PermitRootLogin yes\n")
        titles = [f.title for f in findings]
        assert any("Root login" in t for t in titles)
        root_finding = next(f for f in findings if "Root login" in f.title)
        assert root_finding.severity == Severity.CRITICAL

    def test_permit_root_login_no_produces_no_finding(self) -> None:
        findings = self._scan_with_config(
            "PermitRootLogin no\n"
            "PasswordAuthentication no\n"
            "PermitEmptyPasswords no\n"
            "MaxAuthTries 3\n"
            "X11Forwarding no\n"
            "AllowAgentForwarding no\n"
            "AllowTcpForwarding no\n"
            "LoginGraceTime 60\n"
        )
        assert not any("Root login" in f.title for f in findings)

    def test_password_authentication_yes_is_high(self) -> None:
        findings = self._scan_with_config("PasswordAuthentication yes\n")
        assert any(
            "password authentication" in f.title.lower()
            for f in findings
        )
        pw_finding = next(
            f for f in findings if "password authentication" in f.title.lower()
        )
        assert pw_finding.severity == Severity.HIGH

    def test_empty_passwords_yes_is_critical(self) -> None:
        findings = self._scan_with_config("PermitEmptyPasswords yes\n")
        assert any("empty" in f.title.lower() for f in findings)
        finding = next(f for f in findings if "empty" in f.title.lower())
        assert finding.severity == Severity.CRITICAL

    def test_max_auth_tries_above_threshold_triggers(self) -> None:
        findings = self._scan_with_config("MaxAuthTries 10\n")
        assert any("MaxAuthTries" in f.title for f in findings)

    def test_max_auth_tries_at_threshold_no_finding(self) -> None:
        findings = self._scan_with_config(
            "MaxAuthTries 3\n"
            "PasswordAuthentication no\n"
            "PermitRootLogin no\n"
            "PermitEmptyPasswords no\n"
            "X11Forwarding no\n"
            "AllowAgentForwarding no\n"
            "AllowTcpForwarding no\n"
            "LoginGraceTime 60\n"
        )
        assert not any("MaxAuthTries" in f.title for f in findings)

    def test_protocol_1_is_critical(self) -> None:
        findings = self._scan_with_config("Protocol 1\n")
        assert any("Protocol" in f.title for f in findings)
        proto_finding = next(f for f in findings if "Protocol" in f.title)
        assert proto_finding.severity == Severity.CRITICAL

    def test_protocol_2_no_finding(self) -> None:
        findings = self._scan_with_config(
            "Protocol 2\n"
            "PasswordAuthentication no\n"
            "PermitRootLogin no\n"
            "PermitEmptyPasswords no\n"
            "MaxAuthTries 3\n"
            "X11Forwarding no\n"
            "AllowAgentForwarding no\n"
            "AllowTcpForwarding no\n"
            "LoginGraceTime 60\n"
        )
        assert not any("Protocol" in f.title for f in findings)

    def test_x11_forwarding_yes_is_medium(self) -> None:
        findings = self._scan_with_config("X11Forwarding yes\n")
        assert any("X11" in f.title for f in findings)
        finding = next(f for f in findings if "X11" in f.title)
        assert finding.severity == Severity.MEDIUM

    def test_login_grace_time_above_threshold_triggers(self) -> None:
        findings = self._scan_with_config("LoginGraceTime 300\n")
        assert any("LoginGraceTime" in f.title for f in findings)

    def test_login_grace_time_handles_minutes_format(self) -> None:
        """LoginGraceTime 2m in default config — non-numeric should not crash."""
        auditor = SSHAuditor()
        triggered = auditor._is_triggered("logingracetime", "2m")
        assert isinstance(triggered, bool)  # Should return bool, not raise

    def test_missing_ssh_config_returns_empty(self) -> None:
        auditor = SSHAuditor()
        auditor.SSHD_CONFIG_PATH = "/nonexistent/sshd_config"
        assert auditor.scan() == []

    def test_findings_have_engine_name(self) -> None:
        findings = self._scan_with_config("PermitRootLogin yes\n")
        for f in findings:
            assert f.engine == "ssh_auditor"

    def test_findings_have_positive_weight(self) -> None:
        findings = self._scan_with_config("PermitRootLogin yes\n")
        for f in findings:
            assert f.weight > 0


class TestIsTriggered:
    """Unit tests for the _is_triggered helper method."""

    def test_string_match_triggers_on_bad_value(self) -> None:
        auditor = SSHAuditor()
        assert auditor._is_triggered("permitrootlogin", "yes") is True

    def test_string_match_no_trigger_on_secure_value(self) -> None:
        auditor = SSHAuditor()
        assert auditor._is_triggered("permitrootlogin", "no") is False

    def test_numeric_triggers_when_above_threshold(self) -> None:
        auditor = SSHAuditor()
        assert auditor._is_triggered("maxauthtries", "10") is True

    def test_numeric_no_trigger_at_threshold(self) -> None:
        auditor = SSHAuditor()
        assert auditor._is_triggered("maxauthtries", "3") is False

    def test_numeric_no_trigger_below_threshold(self) -> None:
        auditor = SSHAuditor()
        assert auditor._is_triggered("maxauthtries", "1") is False

    def test_non_numeric_value_does_not_crash(self) -> None:
        auditor = SSHAuditor()
        result = auditor._is_triggered("maxauthtries", "invalid")
        assert isinstance(result, bool)
