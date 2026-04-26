"""Port & Network Scanner — detects open ports and listening services."""
from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass
from typing import List, Optional

from src.scan_runner import Finding, Severity

logger = logging.getLogger(__name__)


@dataclass
class OpenPort:
    """Represents a single listening port parsed from ss output."""
    protocol: str     # tcp or udp
    local_address: str  # e.g. 0.0.0.0 or ::
    port: int
    process: Optional[str]  # process name if available, else None


class PortScanner:
    """Scan for open TCP/UDP ports using ss and flag risky services."""

    SS_COMMAND = ["ss", "-tulnp"]

    # Ports that are dangerous if open — each has a reason and severity
    RISKY_PORTS = {
        21:   ("FTP",             Severity.CRITICAL, 3.0,
               "FTP transmits credentials in plaintext and is a common attack vector."),
        22:   ("SSH",             Severity.INFO,     0.0,
               "SSH is open — ensure key-based auth is enforced."),
        23:   ("Telnet",          Severity.CRITICAL, 3.0,
               "Telnet transmits all data including passwords in plaintext."),
        25:   ("SMTP",            Severity.MEDIUM,   1.5,
               "SMTP open externally may allow mail relay abuse."),
        445:  ("SMB",             Severity.HIGH,     2.5,
               "SMB is frequently exploited; disable if not required."),
        3306: ("MySQL",           Severity.HIGH,     2.5,
               "MySQL port exposed externally risks direct database attacks."),
        3389: ("RDP",             Severity.CRITICAL, 3.0,
               "RDP is a primary ransomware entry point; close or restrict immediately."),
        5900: ("VNC",             Severity.CRITICAL, 3.0,
               "VNC provides full graphical access and is often poorly secured."),
        6379: ("Redis",           Severity.HIGH,     2.5,
               "Redis has no authentication by default; exposure leads to full compromise."),
        8080: ("HTTP Alt",        Severity.LOW,      1.0,
               "Alternative HTTP port open — verify this service is intentional."),
        27017: ("MongoDB",         Severity.HIGH,     2.5,
                "MongoDB exposed without auth allows full database read/write access."),
    }

    # Addresses that mean the port is exposed on all interfaces (dangerous)
    EXPOSED_ADDRESSES = {"0.0.0.0", "::"}

    # ------------------------------------------------------------------ #

    def _run_ss(self) -> str:
        """
        Execute ss -tulnp and return raw stdout.
        Raises RuntimeError if the command fails.
        """
        try:
            result = subprocess.run(
                self.SS_COMMAND,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                logger.error("ss command failed: %s", result.stderr.strip())
                raise RuntimeError(f"ss exited with code {result.returncode}")
            return result.stdout
        except FileNotFoundError:
            logger.error("ss command not found — iproute2 may not be installed")
            raise
        except subprocess.TimeoutExpired:
            logger.error("ss command timed out after 10 seconds")
            raise

    def _parse_port(self, address_port: str) -> tuple[str, int]:
        """
        Parse 'address:port' string from ss output.

        Handles three formats:
          0.0.0.0:22        → IPv4
          [::]:22           → IPv6 (brackets around address)
          *:22              → wildcard
        Returns (address, port) tuple.
        """
        if address_port.startswith("["):
            # IPv6 format: [::]:22
            bracket_end = address_port.index("]")
            address = address_port[1:bracket_end]
            port = int(address_port[bracket_end + 2:])
        elif ":" in address_port:
            # IPv4 format: 0.0.0.0:22
            last_colon = address_port.rfind(":")
            address = address_port[:last_colon]
            port = int(address_port[last_colon + 1:])
        else:
            raise ValueError(f"Cannot parse address:port from: {address_port!r}")

        return address, port

    def _parse_process(self, process_field: str) -> Optional[str]:
        """
        Extract process name from ss process field.

        ss outputs process info like: users:(("sshd",pid=123,fd=4))
        We extract just the name: 'sshd'
        Empty or '-' fields return None.
        """
        if not process_field or process_field == "-":
            return None
        try:
            # Find the first quoted name inside users:(("name",...))
            start = process_field.index('"') + 1
            end = process_field.index('"', start)
            return process_field[start:end]
        except ValueError:
            return None

    def parse_ss_output(self, raw: str) -> List[OpenPort]:
        """
        Parse raw ss -tulnp output into a list of OpenPort objects.

        ss output columns:
        Netid  State  Recv-Q  Send-Q  Local Address:Port  Peer Address:Port  Process
        """
        ports: List[OpenPort] = []

        for lineno, line in enumerate(raw.splitlines(), start=1):
            # Skip header line
            if lineno == 1 or not line.strip():
                continue

            parts = line.split()

            # Minimum: Netid, State, Recv-Q, Send-Q, Local, Peer = 6 columns
            if len(parts) < 6:
                logger.warning("Unexpected ss output line %d: %r", lineno, line)
                continue

            netid = parts[0].lower()          # tcp or udp
            local_field = parts[4]            # Local Address:Port
            process_field = parts[6] if len(parts) > 6 else ""

            # Only process tcp and udp
            if netid not in ("tcp", "udp"):
                continue

            try:
                address, port = self._parse_port(local_field)
            except (ValueError, IndexError) as exc:
                logger.warning("Could not parse port on line %d: %s", lineno, exc)
                continue

            process = self._parse_process(process_field)

            ports.append(OpenPort(
                protocol=netid,
                local_address=address,
                port=port,
                process=process,
            ))

        return ports

    def _build_finding(self, open_port: OpenPort) -> Finding:
        """Build a Finding object for a risky open port."""
        service_name, severity, weight, reason = self.RISKY_PORTS[open_port.port]

        process_info = f" (process: {open_port.process})" if open_port.process else ""
        exposure = "all interfaces" if open_port.local_address in self.EXPOSED_ADDRESSES \
                   else open_port.local_address

        return Finding(
            engine="port_scanner",
            title=f"Risky port {open_port.port} ({service_name}) is open on {exposure}",
            description=(
                f"{reason} "
                f"Port {open_port.port} is listening on {open_port.local_address}"
                f"{process_info}."
            ),
            severity=severity,
            weight=weight,
            fix_command=f"nft add rule inet filter input tcp dport {open_port.port} drop",
            fix_description=(
                f"Block port {open_port.port} with nftables, "
                f"or disable the {service_name} service if not needed."
            ),
        )

    def scan(self) -> List[Finding]:
        """Run port scan and return findings for risky open ports."""
        findings: List[Finding] = []

        logger.info("Starting port scan: %s", " ".join(self.SS_COMMAND))

        try:
            raw = self._run_ss()
        except Exception as exc:
            logger.error("Port scan failed: %s", exc)
            return findings

        open_ports = self.parse_ss_output(raw)
        logger.info("Found %d listening port(s)", len(open_ports))

        for open_port in open_ports:
            if open_port.port not in self.RISKY_PORTS:
                continue

            # Skip INFO severity — SSH open is expected, not a finding
            _, severity, _, _ = self.RISKY_PORTS[open_port.port]
            if severity == Severity.INFO:
                logger.debug("Port %d is INFO — skipping finding", open_port.port)
                continue

            # Only flag ports exposed on all interfaces
            if open_port.local_address not in self.EXPOSED_ADDRESSES:
                logger.debug(
                    "Port %d bound to %s — not externally exposed, skipping",
                    open_port.port, open_port.local_address
                )
                continue

            finding = self._build_finding(open_port)
            logger.debug("Finding: %s", finding.title)
            findings.append(finding)

        logger.info("Port scan complete — %d finding(s)", len(findings))
        return findings
