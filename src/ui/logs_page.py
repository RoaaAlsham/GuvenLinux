# src/ui/logs_page.py
"""Logs page — shows audit history of scans and applied fixes."""
from __future__ import annotations

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk


class LogsPage(Gtk.Box):
    def __init__(self, window):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self._win = window
        self._build()

    def _build(self):
        notebook = Gtk.Notebook()
        notebook.set_vexpand(True)
        self.append(notebook)

        # Scans tab
        self._scan_list = self._make_list()
        scan_scroll = Gtk.ScrolledWindow()
        scan_scroll.set_child(self._scan_list)
        notebook.append_page(scan_scroll, Gtk.Label(label="Scan History"))

        # Fixes tab
        self._fix_list = self._make_list()
        fix_scroll = Gtk.ScrolledWindow()
        fix_scroll.set_child(self._fix_list)
        notebook.append_page(fix_scroll, Gtk.Label(label="Fix History"))

    def _make_list(self) -> Gtk.ListBox:
        lb = Gtk.ListBox()
        lb.add_css_class("boxed-list")
        lb.set_margin_top(8)
        lb.set_margin_bottom(8)
        lb.set_margin_start(12)
        lb.set_margin_end(12)
        return lb

    def refresh(self):
        log = self._win._app.log_mgr

        # Scans
        while (c := self._scan_list.get_first_child()):
            self._scan_list.remove(c)
        for record in log.recent_scans():
            row = Gtk.ListBoxRow()
            lbl = Gtk.Label()
            lbl.set_markup(
                f"<b>{record['timestamp']}</b>  "
                f"Score: <b>{record['score']:.0f}</b>  "
                f"({record['label']})  "
                f"{record['finding_count']} finding(s)"
            )
            lbl.set_halign(Gtk.Align.START)
            lbl.set_margin_top(8)
            lbl.set_margin_bottom(8)
            lbl.set_margin_start(12)
            row.set_child(lbl)
            self._scan_list.append(row)

        # Fixes
        while (c := self._fix_list.get_first_child()):
            self._fix_list.remove(c)
        for record in log.recent_fixes():
            row = Gtk.ListBoxRow()
            status = "✓" if record["success"] else "✗"
            lbl = Gtk.Label()
            lbl.set_markup(
                f"{status}  <b>{record['title']}</b>  "
                f"<span color='#888'>{record['timestamp']}</span>"
            )
            lbl.set_halign(Gtk.Align.START)
            lbl.set_margin_top(8)
            lbl.set_margin_bottom(8)
            lbl.set_margin_start(12)
            row.set_child(lbl)
            self._fix_list.append(row)