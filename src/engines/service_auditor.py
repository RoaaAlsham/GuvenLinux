"""Service Auditor — identifies unnecessary or insecure running services."""
from __future__ import annotations

import json
import logging
import subprocess
from dataclasses import dataclass
from typing import List

from src.scan_runner import Finding, Severity

logger = logging.getLogger(__name__)


@dataclass
class ServiceInfo:
    """Represents a single systemd service unit."""
    unit: str           # e.g. telnet.service
    load: str           # loaded / not-found
    active: str         # active / inactive
    sub: str            # running / dead / exited
    description: str


class ServiceAuditor:
    """Audit enabled systemd services for security issues."""

    SYSTEMCTL_CMD = [
        "systemctl", "list-units",
        "--type=service",
        "--all",
        "--output=json",
        "--no-pager",
    ]

    # Blacklist — service name → (reason, severity, weight, fix)
    DANGEROUS_SERVICES = {
        "telnet.service": (
            "Telnet transmits all data including passwords in plaintext.",
            Severity.CRITICAL, 3.0,
            "systemctl disable --now telnet.service",
        ),
        "telnetd.service": (
            "Telnet daemon exposes the system to credential interception.",
            Severity.CRITICAL, 3.0,
            "systemctl disable --now telnetd.service",
        ),
        "rsh.service": (
            "RSH (Remote Shell) is an obsolete protocol with no encryption.",
            Severity.CRITICAL, 3.0,
            "systemctl disable --now rsh.service",
        ),
        "rlogin.service": (
            "rlogin provides unauthenticated remote access — obsolete and dangerous.",
            Severity.CRITICAL, 3.0,
            "systemctl disable --now rlogin.service",
        ),
        "rexec.service": (
            "rexec executes commands remotely without encryption.",
            Severity.CRITICAL, 3.0,
            "systemctl disable --now rexec.service",
        ),
        "vsftpd.service": (
            "FTP transmits credentials in plaintext. Use SFTP instead.",
            Severity.HIGH, 2.5,
            "systemctl disable --now vsftpd.service",
        ),
        "proftpd.service": (
            "FTP service active — credentials sent unencrypted over the network.",
            Severity.HIGH, 2.5,
            "systemctl disable --now proftpd.service",
        ),
        "pure-ftpd.service": (
            "FTP service active — credentials sent unencrypted over the network.",
            Severity.HIGH, 2.5,
            "systemctl disable --now pure-ftpd.service",
        ),
        "avahi-daemon.service": (
            "Avahi provides mDNS/DNS-SD network discovery — expands attack surface "
            "and is rarely needed on servers.",
            Severity.MEDIUM, 1.5,
            "systemctl disable --now avahi-daemon.service",
        ),
        "cups.service": (
            "CUPS print server is unnecessary on non-desktop systems and has had "
            "critical RCE vulnerabilities.",
            Severity.MEDIUM, 1.5,
            "systemctl disable --now cups.service",
        ),
        "bluetooth.service": (
            "Bluetooth service increases attack surface on servers where "
            "it serves no purpose.",
            Severity.LOW, 1.0,
            "systemctl disable --now bluetooth.service",
        ),
        "nfs-server.service": (
            "NFS server shares filesystems over the network — "
            "disable if file sharing is not required.",
            Severity.HIGH, 2.0,
            "systemctl disable --now nfs-server.service",
        ),
        "rpcbind.service": (
            "rpcbind is required by NFS and other RPC services — "
            "disable if NFS is not in use.",
            Severity.MEDIUM, 1.5,
            "systemctl disable --now rpcbind.service",
        ),
        "smbd.service": (
            "Samba SMB server shares files with Windows clients — "
            "disable if not required.",
            Severity.MEDIUM, 1.5,
            "systemctl disable --now smbd.service",
        ),
        "nmbd.service": (
            "Samba NetBIOS service — disable if Windows file sharing "
            "is not required.",
            Severity.MEDIUM, 1.5,
            "systemctl disable --now nmbd.service",
        ),
        "snmpd.service": (
            "SNMP daemon may expose system information to network — "
            "disable if not actively monitored.",
            Severity.MEDIUM, 1.5,
            "systemctl disable --now snmpd.service",
        ),
        "nis.service": (
            "NIS (Network Information Service) is an obsolete "
            "directory service with known vulnerabilities.",
            Severity.HIGH, 2.0,
            "systemctl disable --now nis.service",
        ),
        "xinetd.service": (
            "xinetd super-server may be running legacy insecure services.",
            Severity.HIGH, 2.0,
            "systemctl disable --now xinetd.service",
        ),
        "inetd.service": (
            "inetd super-server may be running legacy insecure services.",
            Severity.HIGH, 2.0,
            "systemctl disable --now inetd.service",
        ),
    }

    # Socket units that activate dangerous services on demand
    DANGEROUS_SOCKETS = {
        "telnet.socket", "rsh.socket", "rlogin.socket",
        "rexec.socket", "finger.socket",
    }

    # ------------------------------------------------------------------ #

    def _run_systemctl(self) -> str:
        """Execute systemctl and return raw JSON output."""
        try:
            result = subprocess.run(
                self.SYSTEMCTL_CMD,
                capture_output=True,
                text=True,
                timeout=15,
            )
            if result.returncode != 0:
                logger.error(
                    "systemctl failed (code %d): %s",
                    result.returncode, result.stderr.strip()
                )
                raise RuntimeError(
                    f"systemctl exited with code {result.returncode}"
                )
            return result.stdout
        except FileNotFoundError:
            logger.error("systemctl not found — not a systemd system?")
            raise
        except subprocess.TimeoutExpired:
            logger.error("systemctl timed out after 15 seconds")
            raise

    def parse_units(self, raw: str) -> List[ServiceInfo]:
        """
        Parse systemctl JSON output into ServiceInfo objects.

        Handles empty output and malformed JSON gracefully.
        """
        services: List[ServiceInfo] = []

        raw = raw.strip()
        if not raw:
            logger.warning("systemctl returned empty output")
            return services

        try:
            units = json.loads(raw)
        except json.JSONDecodeError as exc:
            logger.error("Failed to parse systemctl JSON: %s", exc)
            return services

        for entry in units:
            try:
                services.append(ServiceInfo(
                    unit=entry["unit"],
                    load=entry.get("load", ""),
                    active=entry.get("active", ""),
                    sub=entry.get("sub", ""),
                    description=entry.get("description", ""),
                ))
            except KeyError as exc:
                logger.warning("Skipping malformed unit entry, missing key: %s", exc)
                continue

        logger.debug("Parsed %d service units", len(services))
        return services

    def _is_active(self, service: ServiceInfo) -> bool:
        """Return True if the service is currently loaded and active."""
        return service.load == "loaded" and service.active == "active"

    def _build_finding(self, service: ServiceInfo) -> Finding:
        """Build a Finding for a dangerous active service."""
        reason, severity, weight, fix_cmd = self.DANGEROUS_SERVICES[service.unit]

        return Finding(
            engine="service_auditor",
            title=f"Dangerous service is active: {service.unit}",
            description=(
                f"{reason} "
                f"Service description: '{service.description}'."
            ),
            severity=severity,
            weight=weight,
            fix_command=fix_cmd,
            fix_description=(
                f"Disable and stop {service.unit} if it is not "
                f"required on this system."
            ),
        )

    def scan(self) -> List[Finding]:
        """Audit running services and return findings."""
        findings: List[Finding] = []

        logger.info("Starting service audit")

        try:
            raw = self._run_systemctl()
        except Exception as exc:
            logger.error("Service audit failed: %s", exc)
            return findings

        services = self.parse_units(raw)
        logger.info("Auditing %d service units", len(services))

        for service in services:
            if service.unit not in self.DANGEROUS_SERVICES:
                continue
            if not self._is_active(service):
                logger.debug(
                    "Dangerous service %s is present but not active — skipping",
                    service.unit
                )
                continue
            finding = self._build_finding(service)
            logger.debug("Finding: %s", finding.title)
            findings.append(finding)

        logger.info("Service audit complete — %d finding(s)", len(findings))
        return findings

