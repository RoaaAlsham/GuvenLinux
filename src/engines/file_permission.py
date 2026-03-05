"""File Permission Auditor — detects insecure file permissions and ownership."""

from __future__ import annotations

from typing import List

from src.scan_runner import Finding


class FilePermissionAuditor:
    """Scan the filesystem for SUID/SGID, world-writable, and mis-owned files."""

    SUID_WHITELIST = {
        "/usr/bin/passwd",
        "/usr/bin/sudo",
        "/usr/bin/su",
        "/usr/bin/newgrp",
        "/usr/bin/chsh",
        "/usr/bin/chfn",
        "/usr/bin/gpasswd",
        "/usr/bin/pkexec",
        "/usr/lib/polkit-1/polkit-agent-helper-1",
    }

    def scan(self) -> List[Finding]:
        """Scan file permissions and return findings."""
        # TODO: Implement find-based permission checks
        return []
