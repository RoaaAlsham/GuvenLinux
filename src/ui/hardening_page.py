"""Hardening Actions page — fix cards with Apply / Skip / Explain."""

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk


class HardeningPage(Gtk.Box):
    """Page showing actionable fix cards with one-click remediation."""

    def __init__(self) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        # TODO: Implement fix cards, progress indicator, before/after preview
