# src/engines/ssh_auditor.py
"""SSH Configuration Auditor — validates sshd_config security parameters."""
from __future__ import annotations

import logging
import os
from typing import List

from src.scan_runner import Finding, Severity

logger = logging.getLogger(__name__)

# Shell snippet appended to every sshd fix command.
#
# Breakdown:
#   systemctl is-active --quiet ssh
#       Checks whether ssh.service is currently running.
#       Exits 0 = active, non-zero = inactive/failed/not-found.
#       --quiet suppresses all output so nothing leaks into the UI message.
#
#   && systemctl reload ssh
#       Only executes when the previous command succeeded (service is active).
#       'reload' sends SIGHUP to sshd, which re-reads sshd_config without
#       dropping existing sessions — safe even when connected over SSH.
#
#   || true
#       If the service is NOT active, is-active exits non-zero and reload is
#       skipped. Without '|| true' the whole shell command would also exit
#       non-zero, causing FixEngine to report the fix as failed even though
#       the config edit succeeded. '|| true' collapses both outcomes (active
#       → reloaded, inactive → skipped) into exit code 0.
#
# The config file edit itself always runs first via 'sed -i ...'.
# The reload is a best-effort live-apply — the new config is on disk
# regardless and will be picked up the next time sshd starts.
_RELOAD_SNIPPET = (
    " && systemctl is-active --quiet ssh && systemctl reload ssh || true"
)


class SSHAuditor:
    """Check /etc/ssh/sshd_config against security best practices."""

    SSHD_CONFIG_PATH = "/etc/ssh/sshd_config"

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

    NUMERIC_PARAMS = {"maxauthtries", "logingracetime"}

    CHECKS = [
        # ── PermitRootLogin ───────────────────────────────────────────
        {
            "key":         "permitrootlogin",
            "bad_values":  ["yes"],
            "severity":    Severity.CRITICAL,
            "title":       "Root login via SSH is permitted with password",
            "description": (
                "PermitRootLogin is set to 'yes', allowing an attacker to "
                "brute-force the root password directly over SSH and gain "
                "immediate full system access with no further escalation needed."
            ),
            "fix_command": (
                "sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/'"
                " /etc/ssh/sshd_config"
                + _RELOAD_SNIPPET
            ),
            "fix_description": "Set PermitRootLogin to 'no' in sshd_config.",
            "weight":      3.0,
        },
        {
            "key":         "permitrootlogin",
            "bad_values":  ["prohibit-password", "without-password"],
            "severity":    Severity.MEDIUM,
            "title":       "Root login via SSH is enabled (key-only)",
            "description": (
                "PermitRootLogin is set to 'prohibit-password' (or the "
                "equivalent 'without-password'). Password-based root login is "
                "blocked, but key-based root login is still allowed. A stolen "
                "or compromised SSH private key grants immediate root access. "
                "Best practice is to disable direct root login entirely and "
                "use a non-root account with sudo instead."
            ),
            "fix_command": (
                "sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/'"
                " /etc/ssh/sshd_config"
                + _RELOAD_SNIPPET
            ),
            "fix_description": (
                "Set PermitRootLogin to 'no'. Ensure a non-root sudo user "
                "exists before applying this change."
            ),
            "weight":      1.5,
        },

        # ── PasswordAuthentication ────────────────────────────────────
        {
            "key":         "passwordauthentication",
            "severity":    Severity.HIGH,
            "title":       "SSH password authentication is enabled",
            "description": (
                "Password authentication allows brute-force attacks. "
                "Key-based authentication is significantly more secure."
            ),
            # No fix_command — applying this automatically could lock the
            # user out if no SSH key is configured. Intentionally manual.
            "fix_command": None,
            "fix_description": (
                "Set 'PasswordAuthentication no' after confirming "
                "key-based auth is working."
            ),
            "weight":      2.5,
        },

        # ── PermitEmptyPasswords ──────────────────────────────────────
        {
            "key":         "permitemptypasswords",
            "severity":    Severity.CRITICAL,
            "title":       "SSH permits empty passwords",
            "description": (
                "Accounts with empty passwords can log in via SSH "
                "with no credentials whatsoever."
            ),
            "fix_command": (
                "sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/'"
                " /etc/ssh/sshd_config"
                + _RELOAD_SNIPPET
            ),
            "fix_description": "Set PermitEmptyPasswords to 'no'.",
            "weight":      3.0,
        },

        # ── MaxAuthTries ──────────────────────────────────────────────
        {
            "key":         "maxauthtries",
            "severity":    Severity.HIGH,
            "title":       "SSH MaxAuthTries is too high",
            "description": (
                "A high MaxAuthTries value gives attackers more attempts "
                "to brute-force credentials before being disconnected."
            ),
            "fix_command": (
                "sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 3/'"
                " /etc/ssh/sshd_config"
                + _RELOAD_SNIPPET
            ),
            "fix_description": "Set MaxAuthTries to 3 or lower.",
            "weight":      2.0,
        },

        # ── Protocol ──────────────────────────────────────────────────
        {
            "key":         "protocol",
            "severity":    Severity.CRITICAL,
            "title":       "SSH Protocol version 1 is allowed",
            "description": (
                "SSH Protocol 1 is cryptographically broken and vulnerable "
                "to man-in-the-middle attacks. Only Protocol 2 should be used."
            ),
            "fix_command": (
                "sed -i 's/^#*Protocol.*/Protocol 2/'"
                " /etc/ssh/sshd_config"
                + _RELOAD_SNIPPET
            ),
            "fix_description": "Set Protocol to '2' in sshd_config.",
            "weight":      3.0,
        },

        # ── X11Forwarding ─────────────────────────────────────────────
        {
            "key":         "x11forwarding",
            "severity":    Severity.MEDIUM,
            "title":       "SSH X11 forwarding is enabled",
            "description": (
                "X11 forwarding can expose the local display to remote "
                "users and is rarely needed on servers."
            ),
            "fix_command": (
                "sed -i 's/^#*X11Forwarding.*/X11Forwarding no/'"
                " /etc/ssh/sshd_config"
                + _RELOAD_SNIPPET
            ),
            "fix_description": "Set X11Forwarding to 'no'.",
            "weight":      1.5,
        },

        # ── AllowAgentForwarding ──────────────────────────────────────
        {
            "key":         "allowagentforwarding",
            "severity":    Severity.MEDIUM,
            "title":       "SSH agent forwarding is enabled",
            "description": (
                "Agent forwarding allows a compromised server to use "
                "your SSH keys to authenticate to other servers."
            ),
            "fix_command": (
                "sed -i 's/^#*AllowAgentForwarding.*/AllowAgentForwarding no/'"
                " /etc/ssh/sshd_config"
                + _RELOAD_SNIPPET
            ),
            "fix_description": "Set AllowAgentForwarding to 'no'.",
            "weight":      1.5,
        },

        # ── AllowTcpForwarding ────────────────────────────────────────
        {
            "key":         "allowtcpforwarding",
            "severity":    Severity.MEDIUM,
            "title":       "SSH TCP forwarding is enabled",
            "description": (
                "TCP forwarding tunnels traffic through your server, "
                "potentially bypassing firewall rules."
            ),
            "fix_command": (
                "sed -i 's/^#*AllowTcpForwarding.*/AllowTcpForwarding no/'"
                " /etc/ssh/sshd_config"
                + _RELOAD_SNIPPET
            ),
            "fix_description": "Set AllowTcpForwarding to 'no'.",
            "weight":      1.5,
        },

        # ── LoginGraceTime ────────────────────────────────────────────
        {
            "key":         "logingracetime",
            "severity":    Severity.LOW,
            "title":       "SSH LoginGraceTime is too long",
            "description": (
                "A long grace time keeps unauthenticated connections open "
                "longer, enabling slow denial-of-service attacks."
            ),
            "fix_command": (
                "sed -i 's/^#*LoginGraceTime.*/LoginGraceTime 60/'"
                " /etc/ssh/sshd_config"
                + _RELOAD_SNIPPET
            ),
            "fix_description": "Set LoginGraceTime to 60 seconds or lower.",
            "weight":      1.0,
        },
    ]

    # ------------------------------------------------------------------ #

    def parse_config(self, path: str) -> dict[str, str]:
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
        key = check["key"]

        if "bad_values" in check:
            return value in check["bad_values"]

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

        secure_value = self.SECURE_DEFAULTS.get(
            next((k for k in self.SECURE_DEFAULTS if k.lower() == key), key),
            "",
        ).lower()
        return value != secure_value

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []

        if not os.path.exists(self.SSHD_CONFIG_PATH):
            logger.info("SSH config not found — skipping SSH audit")
            return findings

        logger.info(
            "Starting SSH configuration audit: %s", self.SSHD_CONFIG_PATH
        )
        config = self.parse_config(self.SSHD_CONFIG_PATH)
        effective = {**self.SSH_DEFAULTS, **config}

        for check in self.CHECKS:
            key   = check["key"]
            value = effective.get(key, "")

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