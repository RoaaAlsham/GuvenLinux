"""Overview / Home dashboard page — score dial and severity breakdown."""

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk


class DashboardPage(Gtk.Box):
    """Home page showing overall security score and quick scan button."""

    def __init__(self) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        # TODO: Implement score dial, severity bar, last-scan info, Quick Scan button
