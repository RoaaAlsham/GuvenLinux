"""SSH Configuration Auditor — validates sshd_config security parameters."""

from __future__ import annotations

from typing import List

from src.scan_runner import Finding


class SSHAuditor:
    """Check /etc/ssh/sshd_config against security best practices."""

    SSHD_CONFIG_PATH = "/etc/ssh/sshd_config"

    SECURE_DEFAULTS = {
        "PermitRootLogin": "no",
        "PasswordAuthentication": "no",
        "MaxAuthTries": "3",
        "LoginGraceTime": "60",
        "Protocol": "2",
        "X11Forwarding": "no",
        "PermitEmptyPasswords": "no",
        "AllowAgentForwarding": "no",
        "AllowTcpForwarding": "no",
    }

    def scan(self) -> List[Finding]:
        """Audit SSH configuration and return findings."""
        # TODO: Implement sshd_config parsing and validation
        return []
