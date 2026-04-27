"""Settings persistence using JSON config file."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

CONFIG_DIR = Path.home() / ".config" / "linuxguard"
CONFIG_FILE = CONFIG_DIR / "settings.json"

DEFAULTS: Dict[str, Any] = {
    "scan_schedule_enabled": False,
    "scan_schedule_interval_hours": 24,
    "notification_enabled": True,
    "theme": "system",
    "exclusions": [],
}


class ConfigManager:
    """Read and write application settings."""

    def __init__(self) -> None:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        self._config: Dict[str, Any] = dict(DEFAULTS)
        self._load()

    def _load(self) -> None:
        if CONFIG_FILE.exists():
            with open(CONFIG_FILE, encoding="utf-8") as f:
                self._config.update(json.load(f))

    def save(self) -> None:
        """Persist current settings to disk."""
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(self._config, f, indent=2, ensure_ascii=False)

    def get(self, key: str) -> Any:
        """Get a setting value."""
        return self._config.get(key, DEFAULTS.get(key))

    def set(self, key: str, value: Any) -> None:
        """Set a setting value."""
        self._config[key] = value
