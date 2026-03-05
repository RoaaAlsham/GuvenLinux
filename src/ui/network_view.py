"""Network View page — live open ports table with block capability."""

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk


class NetworkViewPage(Gtk.Box):
    """Page showing open ports, protocols, PIDs, and nftables rule preview."""

    def __init__(self) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        # TODO: Implement port table, protocol/PID columns, Block Port button
