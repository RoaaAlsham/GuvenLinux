"""Settings page — scan schedule, exclusions, theme, notifications."""

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk


class SettingsPage(Gtk.Box):
    """Application settings and preferences page."""

    def __init__(self) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        # TODO: Implement settings controls wired to ConfigManager
