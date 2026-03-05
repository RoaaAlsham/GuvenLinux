"""Scan Results page — findings list grouped by engine."""

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk


class ScanResultsPage(Gtk.Box):
    """Page displaying all findings with filtering and expandable rows."""

    def __init__(self) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        # TODO: Implement findings list with severity badges and fix preview
