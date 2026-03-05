"""Entry point for PardusGuard application."""

import sys

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk

from src.main_window import MainWindow


APP_ID = "org.pardus.pardusguard"


class PardusGuardApp(Gtk.Application):
    """Main GTK4 application class."""

    def __init__(self) -> None:
        super().__init__(application_id=APP_ID)

    def do_activate(self) -> None:
        window = MainWindow(application=self)
        window.present()


def main() -> None:
    """Launch PardusGuard."""
    app = PardusGuardApp()
    app.run(sys.argv)


if __name__ == "__main__":
    main()
