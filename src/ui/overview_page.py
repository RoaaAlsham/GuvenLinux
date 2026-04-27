# src/ui/overview_page.py
"""Overview page — shows the security score and a summary."""
from __future__ import annotations

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, Pango

from src.scan_runner import ScanResult, Severity


SCORE_COLORS = {
    "Secure":        "#2ec27e",
    "Moderate Risk": "#f5c211",
    "High Risk":     "#e66100",
    "Critical":      "#c01c28",
}


class OverviewPage(Gtk.Box):
    def __init__(self, window):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=24)
        self._win = window
        self.set_margin_top(32)
        self.set_margin_bottom(32)
        self.set_margin_start(32)
        self.set_margin_end(32)
        self._build()

    def _build(self):
        # Score circle (simulated with a big label)
        self._score_label = Gtk.Label(label="—")
        self._score_label.set_markup(
            '<span font="72" weight="bold" color="#888">—</span>'
        )
        self.append(self._score_label)

        # Status label
        self._status_label = Gtk.Label(label="No scan yet")
        self._status_label.set_markup('<span font="24">No scan yet</span>')
        self.append(self._status_label)

        # Separator
        self.append(Gtk.Separator())

        # Severity breakdown
        grid = Gtk.Grid()
        grid.set_column_spacing(32)
        grid.set_row_spacing(8)
        grid.set_halign(Gtk.Align.CENTER)
        self.append(grid)

        self._counts: dict[Severity, Gtk.Label] = {}
        for col, sev in enumerate([
            Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
            Severity.LOW, Severity.INFO,
        ]):
            lbl_title = Gtk.Label(label=sev.value)
            lbl_title.add_css_class("caption")
            grid.attach(lbl_title, col, 0, 1, 1)

            lbl_count = Gtk.Label(label="0")
            lbl_count.set_markup(f'<span font="20" weight="bold">0</span>')
            grid.attach(lbl_count, col, 1, 1, 1)
            self._counts[sev] = lbl_count

        # Quick actions
        scan_btn = Gtk.Button(label="Run Scan Now")
        scan_btn.add_css_class("suggested-action")
        scan_btn.set_halign(Gtk.Align.CENTER)
        scan_btn.connect("clicked", lambda _: self._win._on_scan_clicked(None))
        self.append(scan_btn)

    def update(self, result: ScanResult):
        score = result.score
        label = result.label
        color = SCORE_COLORS.get(label, "#888888")

        self._score_label.set_markup(
            f'<span font="72" weight="bold" color="{color}">'
            f'{score:.0f}</span>'
        )
        self._status_label.set_markup(
            f'<span font="24" color="{color}">{label}</span>'
        )

        # Count findings per severity
        counts = {s: 0 for s in Severity}
        for f in result.findings:
            counts[f.severity] += 1

        for sev, lbl in self._counts.items():
            lbl.set_markup(
                f'<span font="20" weight="bold">{counts[sev]}</span>'
            )