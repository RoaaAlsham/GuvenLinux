"""Tests for SSH Configuration Auditor engine."""

from src.engines.ssh_auditor import SSHAuditor


class TestSSHAuditor:
    """SSH auditor test cases."""

    def test_secure_defaults_defined(self) -> None:
        auditor = SSHAuditor()
        assert "PermitRootLogin" in auditor.SECURE_DEFAULTS
        assert auditor.SECURE_DEFAULTS["PermitRootLogin"] == "no"

    def test_scan_returns_list(self) -> None:
        auditor = SSHAuditor()
        results = auditor.scan()
        assert isinstance(results, list)
