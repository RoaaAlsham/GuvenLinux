# src/fix_engine.py
"""Remediation executor — applies fixes via PolicyKit (pkexec)."""
from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class FixAction:
    """A single remediation action that can be applied to the system."""
    action_id: str
    title: str
    command: str
    requires_root: bool = True
    auto_apply_safe: bool = False
    rollback_command: str | None = None


class FixEngine:
    """
    Executes fix actions with privilege escalation via pkexec.

    Flow:
      1. Wrap the command in pkexec sh -c "..." if root is required.
         Using 'sh -c' means the full shell string — including &&, ||,
         and multi-command chains — is interpreted correctly. 
      2. Run with a timeout so a hung pkexec dialog doesn't freeze the UI.
      3. Interpret the exit code and return a (success, message) tuple.
    """

    def apply(self, action: FixAction) -> tuple[bool, str]:
        """
        Apply a fix action.

        Returns (success: bool, human_readable_message: str).
        Always returns — never raises — so the UI thread is never blocked
        by an unexpected exception.
        """
        logger.info(
            "Applying fix: %s | command: %s", action.title, action.command
        )

        # Build the command list for subprocess.
        if action.requires_root:
            cmd = ["pkexec", "sh", "-c", action.command]
        else:
            cmd = ["sh", "-c", action.command]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )
            # Merge stdout and stderr — both can carry useful context
            output = (result.stdout + result.stderr).strip()

            if result.returncode == 0:
                logger.info("Fix applied successfully: %s", action.title)
                # Give the user a more specific message depending on whether
                # the reload snippet actually reloaded the service.
                # We can't know for certain from the exit code alone, but
                # if the output is empty it means sed succeeded and
                # is-active exited non-zero (service inactive) → skipped.
                msg = output if output else (
                    "Configuration updated. "
                    "SSH service was not running — changes will apply on next start."
                )
                return True, msg

            else:
                # A non-zero exit means sed itself failed or pkexec was
                # cancelled by the user (pkexec exits 126 on cancel/auth fail).
                if result.returncode == 126:
                    msg = "Authentication cancelled or PolicyKit denied the request."
                elif result.returncode == 127:
                    msg = "pkexec could not find the command to run."
                else:
                    msg = output or f"Command exited with code {result.returncode}."

                logger.error(
                    "Fix failed (code %d): %s | output: %s",
                    result.returncode, action.title, output,
                )
                return False, msg

        except subprocess.TimeoutExpired:
            msg = "Command timed out after 30 seconds."
            logger.error("Timeout applying fix: %s", action.title)
            return False, msg

        except FileNotFoundError:
            msg = "pkexec not found — PolicyKit may not be installed on this system."
            logger.error(msg)
            return False, msg

        except Exception as exc:
            msg = f"Unexpected error: {exc}"
            logger.error("Error applying %s: %s", action.title, exc, exc_info=True)
            return False, msg

    def preview(self, action: FixAction) -> str:
        """Return the exact shell string that would be executed."""
        prefix = "pkexec sh -c " if action.requires_root else "sh -c "
        return f"{prefix}'{action.command}'"