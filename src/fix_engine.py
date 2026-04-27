# src/fix_engine.py
"""Remediation executor — applies fixes via PolicyKit (pkexec)."""
from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class FixAction:
    action_id: str
    title: str
    command: str
    requires_root: bool = True
    auto_apply_safe: bool = False
    rollback_command: str | None = None


class FixEngine:
    """
    Executes fix actions with privilege escalation via pkexec.

    For each action:
      1. Log what we're about to do (audit trail)
      2. Run the command via pkexec so PolicyKit handles the auth dialog
      3. Log success or failure
      4. Return True/False to the caller

    The GTK layer should call this from a background thread
    (use GLib.idle_add to report results back to the UI).
    """

    def apply(self, action: FixAction) -> tuple[bool, str]:
        """
        Apply a fix action.

        Returns (success: bool, message: str).
        Message is the stdout/stderr output — display it in the UI.
        """
        logger.info("Applying fix: %s | command: %s", action.title, action.command)

        cmd = action.command.split()

        # Prefix with pkexec when root is required
        if action.requires_root:
            cmd = ["pkexec"] + cmd

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )
            output = (result.stdout + result.stderr).strip()

            if result.returncode == 0:
                logger.info("Fix applied successfully: %s", action.title)
                return True, output or "Applied successfully."
            else:
                logger.error(
                    "Fix failed (code %d): %s | output: %s",
                    result.returncode, action.title, output
                )
                return False, output or f"Command exited with code {result.returncode}"

        except subprocess.TimeoutExpired:
            msg = f"Command timed out after 30 seconds: {action.title}"
            logger.error(msg)
            return False, msg
        except FileNotFoundError:
            msg = "pkexec not found — PolicyKit may not be installed."
            logger.error(msg)
            return False, msg
        except Exception as exc:
            logger.error("Unexpected error applying %s: %s", action.title, exc)
            return False, str(exc)

    def preview(self, action: FixAction) -> str:
        """Return the exact command string that would be run."""
        prefix = "pkexec " if action.requires_root else ""
        return f"{prefix}{action.command}"