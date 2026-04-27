# src/ui/scan_results_page.py
"""Scan results page — lists all findings with severity badges."""
from __future__ import annotations

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk

from src.scan_runner import Finding, ScanResult, Severity


SEVERITY_CSS = {
    Severity.CRITICAL: "error",
    Severity.HIGH:     "warning",
    Severity.MEDIUM:   "accent",
    Severity.LOW:      "success",
    Severity.INFO:     "dim-label",
}


class ScanResultsPage(Gtk.Box):
    def __init__(self, window):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self._win = window
        self._build()

    def _build(self):
        # Toolbar with filter
        toolbar = Gtk.Box(spacing=8)
        toolbar.set_margin_top(8)
        toolbar.set_margin_bottom(8)
        toolbar.set_margin_start(12)
        toolbar.set_margin_end(12)

        lbl = Gtk.Label(label="Filter:")
        toolbar.append(lbl)

        self._filter_combo = Gtk.DropDown.new_from_strings(
            ["All", "Critical", "High", "Medium", "Low", "Info"]
        )
        self._filter_combo.connect("notify::selected", self._on_filter_changed)
        toolbar.append(self._filter_combo)

        self._count_label = Gtk.Label(label="0 findings")
        self._count_label.set_hexpand(True)
        self._count_label.set_halign(Gtk.Align.END)
        toolbar.append(self._count_label)
        self.append(toolbar)

        self.append(Gtk.Separator())

        # Scrollable findings list
        scroll = Gtk.ScrolledWindow()
        scroll.set_vexpand(True)
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        self.append(scroll)

        self._list_box = Gtk.ListBox()
        self._list_box.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self._list_box.add_css_class("boxed-list")
        self._list_box.set_margin_top(8)
        self._list_box.set_margin_bottom(8)
        self._list_box.set_margin_start(12)
        self._list_box.set_margin_end(12)
        scroll.set_child(self._list_box)

        self._findings: list[Finding] = []
        self._selected_filter = "All"

    def update(self, result: ScanResult):
        self._findings = result.findings
        self._rebuild_list()

    def _on_filter_changed(self, combo, _):
        labels = ["All", "Critical", "High", "Medium", "Low", "Info"]
        self._selected_filter = labels[combo.get_selected()]
        self._rebuild_list()

    def _rebuild_list(self):
        # Remove old rows
        while (child := self._list_box.get_first_child()):
            self._list_box.remove(child)

        shown = [
            f for f in self._findings
            if self._selected_filter == "All"
            or f.severity.value == self._selected_filter
        ]

        self._count_label.set_label(f"{len(shown)} finding(s)")

        for finding in shown:
            row = self._make_row(finding)
            self._list_box.append(row)

    def _make_row(self, finding: Finding) -> Gtk.ListBoxRow:
        row = Gtk.ListBoxRow()
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        box.set_margin_top(10)
        box.set_margin_bottom(10)
        box.set_margin_start(12)
        box.set_margin_end(12)

        # Top line: badge + title
        top = Gtk.Box(spacing=8)

        badge = Gtk.Label(label=finding.severity.value)
        badge.add_css_class(SEVERITY_CSS.get(finding.severity, ""))
        badge.add_css_class("caption")
        top.append(badge)

        title = Gtk.Label(label=finding.title)
        title.set_halign(Gtk.Align.START)
        title.set_markup(f"<b>{finding.title}</b>")
        top.append(title)

        box.append(top)

        # Description
        desc = Gtk.Label(label=finding.description)
        desc.set_halign(Gtk.Align.START)
        desc.set_wrap(True)
        desc.add_css_class("caption")
        box.append(desc)

        row.set_child(box)
        return row