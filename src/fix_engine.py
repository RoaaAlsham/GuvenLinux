"""Remediation executor — applies pre-vetted fix actions via PolicyKit."""

from __future__ import annotations

from dataclasses import dataclass


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
    """Executes fix actions with backup, verification, and logging."""

    def apply(self, action: FixAction) -> bool:
        """Apply a fix action. Returns True on success."""
        # TODO: Implement backup → apply → verify → log pipeline
        return False

    def preview(self, action: FixAction) -> str:
        """Return the exact command that would be run."""
        return action.command
