"""Logs page — timestamped audit log with filtering and export."""

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk


class LogsPage(Gtk.Box):
    """Page displaying the audit log with type/date filters."""

    def __init__(self) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        # TODO: Implement log viewer, filters, and export button
