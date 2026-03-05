"""Service Auditor — identifies unnecessary or insecure running services."""

from __future__ import annotations

from typing import List

from src.scan_runner import Finding


class ServiceAuditor:
    """Audit enabled systemd services for security issues."""

    UNNECESSARY_SERVICES = [
        "telnet.socket",
        "rsh.socket",
        "avahi-daemon.service",
        "cups.service",
    ]

    def scan(self) -> List[Finding]:
        """Audit running services and return findings."""
        # TODO: Implement systemctl list-units parsing
        return []
