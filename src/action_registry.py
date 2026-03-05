"""Registry of all pre-vetted fix actions."""

from __future__ import annotations

from typing import Dict

from src.fix_engine import FixAction


class ActionRegistry:
    """Central registry mapping finding types to their fix actions."""

    def __init__(self) -> None:
        self._actions: Dict[str, FixAction] = {}

    def register(self, finding_key: str, action: FixAction) -> None:
        """Register a fix action for a specific finding type."""
        self._actions[finding_key] = action

    def get(self, finding_key: str) -> FixAction | None:
        """Look up the fix action for a finding type."""
        return self._actions.get(finding_key)

    def all_actions(self) -> Dict[str, FixAction]:
        """Return all registered actions."""
        return dict(self._actions)
