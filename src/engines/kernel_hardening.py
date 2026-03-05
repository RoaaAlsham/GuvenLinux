"""Kernel & OS Hardening — checks sysctl parameters against hardened baseline."""

from __future__ import annotations

from typing import Dict, List

from src.scan_runner import Finding


class KernelHardening:
    """Validate kernel parameters for security hardening compliance."""

    HARDENED_PARAMS: Dict[str, str] = {
        "kernel.randomize_va_space": "2",
        "net.ipv4.tcp_syncookies": "1",
        "net.ipv4.ip_forward": "0",
        "net.ipv4.conf.all.accept_redirects": "0",
        "net.ipv4.conf.all.send_redirects": "0",
        "net.ipv4.conf.all.accept_source_route": "0",
        "kernel.core_pattern": "|/bin/false",
        "fs.suid_dumpable": "0",
        "kernel.dmesg_restrict": "1",
        "kernel.kptr_restrict": "2",
    }

    def scan(self) -> List[Finding]:
        """Check kernel params and return findings."""
        # TODO: Implement sysctl parsing and comparison
        return []
