"""SSH Configuration Auditor — validates sshd_config security parameters."""
from __future__ import annotations

import logging
import os
from typing import List

from src.scan_runner import Finding, Severity

logger = logging.getLogger(__name__)


class SSHAuditor:
    """Check /etc/ssh/sshd_config against security best practices."""

    SSHD_CONFIG_PATH = "/etc/ssh/sshd_config"

    # SSH daemon built-in defaults when a parameter is commented out or absent
    SSH_DEFAULTS = {
        "permitrootlogin":        "prohibit-password",
        "passwordauthentication": "yes",
        "maxauthtries":           "6",
        "logingracetime":         "120",
        "x11forwarding":          "no",
        "permitemptypasswords":   "no",
        "allowagentforwarding":   "yes",
        "allowtcpforwarding":     "yes",
        "protocol":               "2",
    }

    # what we consider fully secure
    SECURE_DEFAULTS = {
        "PermitRootLogin":        "no",
        "PasswordAuthentication": "no",
        "MaxAuthTries":           "3",
        "LoginGraceTime":         "60",
        "Protocol":               "2",
        "X11Forwarding":          "no",
        "PermitEmptyPasswords":   "no",
        "AllowAgentForwarding":   "no",
        "AllowTcpForwarding":     "no",
    }

    # Numeric parameters — compared as integers, not strings
    NUMERIC_PARAMS = {"maxauthtries", "logingracetime"}

    # ------------------------------------------------------------------ #
    # Check definitions
    # ------------------------------------------------------------------ #

    CHECKS = [
        # ── PermitRootLogin ───────────────────────────────────────────
        {
            "key":             "permitrootlogin",
            "bad_values":      ["yes"],          # password-based root login
            "severity":        Severity.CRITICAL,
            "title":           "Root login via SSH is permitted with password",
            "description":     (
                "PermitRootLogin is set to 'yes', allowing an attacker to "
                "brute-force the root password directly over SSH and gain "
                "immediate full system access with no further escalation needed."
            ),
            "fix_command":     (
                "sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/'"
                " /etc/ssh/sshd_config && systemctl reload ssh"
            ),
            "fix_description": "Set PermitRootLogin to 'no' in sshd_config",
            "weight":          3.0,
        },
        {
            "key":             "permitrootlogin",
            "bad_values":      ["prohibit-password", "without-password"],
            "severity":        Severity.MEDIUM,
            "title":           "Root login via SSH is enabled (key-only)",
            "description":     (
                "PermitRootLogin is set to 'prohibit-password' (or the "
                "equivalent 'without-password'). Password-based root login is "
                "blocked, but key-based root login is still allowed. A stolen "
                "or compromised SSH private key grants immediate root access. "
                "Best practice is to disable direct root login entirely and "
                "use a non-root account with sudo instead."
            ),
            "fix_command":     (
                "sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/'"
                " /etc/ssh/sshd_config && systemctl reload ssh"
            ),
            "fix_description": (
                "Set PermitRootLogin to 'no'. Ensure a non-root sudo user "
                "exists before applying this change."
            ),
            "weight":          1.5,
        },

        # ── All other checks (unchanged behaviour) ────────────────────
        {
            "key":             "passwordauthentication",
            "severity":        Severity.HIGH,
            "title":           "SSH password authentication is enabled",
            "description":     (
                "Password authentication allows brute-force attacks. "
                "Key-based authentication is significantly more secure."
            ),
            "fix_command":     None,
            "fix_description": (
                "Set 'PasswordAuthentication no' after confirming "
                "key-based auth is working."
            ),
            "weight":          2.5,
        },
        {
            "key":             "permitemptypasswords",
            "severity":        Severity.CRITICAL,
            "title":           "SSH permits empty passwords",
            "description":     (
                "Accounts with empty passwords can log in via SSH "
                "with no credentials whatsoever."
            ),
            "fix_command":     (
                "sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/'"
                " /etc/ssh/sshd_config && systemctl reload ssh"
            ),
            "fix_description": "Set PermitEmptyPasswords to 'no'.",
            "weight":          3.0,
        },
        {
            "key":             "maxauthtries",
            "severity":        Severity.HIGH,
            "title":           "SSH MaxAuthTries is too high",
            "description":     (
                "A high MaxAuthTries value gives attackers more attempts "
                "to brute-force credentials before being disconnected."
            ),
            "fix_command":     (
                "sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 3/'"
                " /etc/ssh/sshd_config && systemctl reload ssh"
            ),
            "fix_description": "Set MaxAuthTries to 3 or lower.",
            "weight":          2.0,
        },
        {
            "key":             "protocol",
            "severity":        Severity.CRITICAL,
            "title":           "SSH Protocol version 1 is allowed",
            "description":     (
                "SSH Protocol 1 is cryptographically broken and vulnerable "
                "to man-in-the-middle attacks. Only Protocol 2 should be used."
            ),
            "fix_command":     (
                "sed -i 's/^#*Protocol.*/Protocol 2/'"
                " /etc/ssh/sshd_config && systemctl reload ssh"
            ),
            "fix_description": "Set Protocol to '2' in sshd_config.",
            "weight":          3.0,
        },
        {
            "key":             "x11forwarding",
            "severity":        Severity.MEDIUM,
            "title":           "SSH X11 forwarding is enabled",
            "description":     (
                "X11 forwarding can expose the local display to remote "
                "users and is rarely needed on servers."
            ),
            "fix_command":     (
                "sed -i 's/^#*X11Forwarding.*/X11Forwarding no/'"
                " /etc/ssh/sshd_config && systemctl reload ssh"
            ),
            "fix_description": "Set X11Forwarding to 'no'.",
            "weight":          1.5,
        },
        {
            "key":             "allowagentforwarding",
            "severity":        Severity.MEDIUM,
            "title":           "SSH agent forwarding is enabled",
            "description":     (
                "Agent forwarding allows a compromised server to use "
                "your SSH keys to authenticate to other servers."
            ),
            "fix_command":     (
                "sed -i 's/^#*AllowAgentForwarding.*/AllowAgentForwarding no/'"
                " /etc/ssh/sshd_config && systemctl reload ssh"
            ),
            "fix_description": "Set AllowAgentForwarding to 'no'.",
            "weight":          1.5,
        },
        {
            "key":             "allowtcpforwarding",
            "severity":        Severity.MEDIUM,
            "title":           "SSH TCP forwarding is enabled",
            "description":     (
                "TCP forwarding tunnels traffic through your server, "
                "potentially bypassing firewall rules."
            ),
            "fix_command":     (
                "sed -i 's/^#*AllowTcpForwarding.*/AllowTcpForwarding no/'"
                " /etc/ssh/sshd_config && systemctl reload ssh"
            ),
            "fix_description": "Set AllowTcpForwarding to 'no'.",
            "weight":          1.5,
        },
        {
            "key":             "logingracetime",
            "severity":        Severity.LOW,
            "title":           "SSH LoginGraceTime is too long",
            "description":     (
                "A long grace time keeps unauthenticated connections open "
                "longer, enabling slow denial-of-service attacks."
            ),
            "fix_command":     (
                "sed -i 's/^#*LoginGraceTime.*/LoginGraceTime 60/'"
                " /etc/ssh/sshd_config && systemctl reload ssh"
            ),
            "fix_description": "Set LoginGraceTime to 60 seconds or lower.",
            "weight":          1.0,
        },
    ]

    # ------------------------------------------------------------------ #

    def parse_config(self, path: str) -> dict[str, str]:
        """
        Parse sshd_config and return active key-value pairs.

        Skips blank lines and comments. Keys are lowercased.
        """
        config: dict[str, str] = {}

        try:
            with open(path, "r") as f:
                for lineno, line in enumerate(f, start=1):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        key, value = parts
                        config[key.lower()] = value.lower()
                    else:
                        logger.warning(
                            "sshd_config line %d has unexpected format: %r",
                            lineno, line,
                        )
        except FileNotFoundError:
            logger.info(
                "sshd_config not found at %s — SSH may not be installed", path
            )
        except PermissionError:
            logger.error(
                "Permission denied reading %s — run with sufficient privileges",
                path,
            )
        except OSError as exc:
            logger.error("Failed to read %s: %s", path, exc)

        return config

    def _is_triggered(self, check: dict, value: str) -> bool:
        """
        Decide whether a config value fails a specific check.

        Two evaluation paths:

        1. Explicit bad_values list (used by permitrootlogin checks):
               triggered  ←→  value in check["bad_values"]
           This lets two separate check entries cover "yes" (CRITICAL)
           and "prohibit-password" (MEDIUM) independently.

        2. Numeric threshold (maxauthtries, logingracetime):
               triggered  ←→  int(value) > int(secure_threshold)

        3. String equality fallback (all other keys):
               triggered  ←→  value != secure_value
        """
        key = check["key"]

        # Path 1 — explicit bad-value membership test
        if "bad_values" in check:
            return value in check["bad_values"]

        # Path 2 — numeric threshold comparison
        if key in self.NUMERIC_PARAMS:
            secure_value = self.SECURE_DEFAULTS.get(
                next((k for k in self.SECURE_DEFAULTS if k.lower() == key), key),
                "0",
            ).lower()
            try:
                return int(value) > int(secure_value)
            except ValueError:
                logger.warning("Non-numeric value for %s: %r", key, value)
                return False

        # Path 3 — plain string comparison against SECURE_DEFAULTS
        secure_value = self.SECURE_DEFAULTS.get(
            next((k for k in self.SECURE_DEFAULTS if k.lower() == key), key),
            "",
        ).lower()
        return value != secure_value

    def scan(self) -> List[Finding]:
        """Audit SSH configuration and return findings."""
        findings: List[Finding] = []

        if not os.path.exists(self.SSHD_CONFIG_PATH):
            logger.info("SSH config not found — skipping SSH audit")
            return findings

        logger.info(
            "Starting SSH configuration audit: %s", self.SSHD_CONFIG_PATH
        )
        config = self.parse_config(self.SSHD_CONFIG_PATH)

        # Merge file values over daemon built-in defaults
        effective = {**self.SSH_DEFAULTS, **config}

        for check in self.CHECKS:
            key   = check["key"]
            value = effective.get(key, "")

            # Pass the whole check dict 
            if self._is_triggered(check, value):
                logger.debug(
                    "Finding triggered: %s (value=%r)", check["title"], value
                )
                findings.append(Finding(
                    engine="ssh_auditor",
                    title=check["title"],
                    description=check["description"],
                    severity=check["severity"],
                    weight=check["weight"],
                    fix_command=check["fix_command"],
                    fix_description=check["fix_description"],
                ))

        logger.info("SSH audit complete — %d finding(s)", len(findings))
        return findings