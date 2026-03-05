"""GTK4 application window with sidebar navigation."""

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk


class MainWindow(Gtk.ApplicationWindow):
    """Primary application window containing sidebar and page stack."""

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.set_title("PardusGuard")
        self.set_default_size(1024, 700)
        self._build_ui()

    def _build_ui(self) -> None:
        """Construct the sidebar + stack layout."""
        # TODO: Implement sidebar navigation and page stack
        pass
