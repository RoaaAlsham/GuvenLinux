"""Reports page — PDF/JSON export and scan history timeline."""

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk


class ReportsPage(Gtk.Box):
    """Page for exporting reports and viewing scan history."""

    def __init__(self) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        # TODO: Implement export buttons, scan history timeline, comparison view
