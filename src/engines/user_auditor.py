"""User & Authentication Auditor — checks user accounts and auth policies."""

from __future__ import annotations

from typing import List

from src.scan_runner import Finding


class UserAuditor:
    """Audit user accounts, passwords, and sudo configuration."""

    def scan(self) -> List[Finding]:
        """Audit user accounts and return findings."""
        # TODO: Implement /etc/passwd, /etc/shadow, /etc/sudoers parsing
        return []
