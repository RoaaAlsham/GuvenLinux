"""Port & Network Scanner — detects open ports and listening services."""

from __future__ import annotations

from typing import List

from src.scan_runner import Finding


class PortScanner:
    """Scan for open TCP/UDP ports using ss and flag risky services."""

    RISKY_PORTS = {21, 23, 3389, 5900}

    def scan(self) -> List[Finding]:
        """Run port scan and return findings."""
        # TODO: Implement ss -tulnp parsing
        return []
