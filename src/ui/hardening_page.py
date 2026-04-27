# src/ui/hardening_page.py
"""Hardening actions page — apply fixes with one click."""
from __future__ import annotations

import threading

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, GLib

from src.scan_runner import Finding, ScanResult
from src.fix_engine import FixAction


class HardeningPage(Gtk.Box):
    def __init__(self, window):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self._win = window
        self._build()

    def _build(self):
        header = Gtk.Label()
        header.set_markup("<b>Hardening Actions</b>")
        header.set_halign(Gtk.Align.START)
        header.set_margin_top(16)
        header.set_margin_start(16)
        self.append(header)

        sub = Gtk.Label(
            label="Applying a fix will run the recommended command with administrator privileges."
        )
        sub.set_halign(Gtk.Align.START)
        sub.set_margin_start(16)
        sub.set_margin_bottom(8)
        sub.add_css_class("caption")
        self.append(sub)

        self.append(Gtk.Separator())

        scroll = Gtk.ScrolledWindow()
        scroll.set_vexpand(True)
        self.append(scroll)

        self._list_box = Gtk.ListBox()
        self._list_box.add_css_class("boxed-list")
        self._list_box.set_margin_top(8)
        self._list_box.set_margin_bottom(8)
        self._list_box.set_margin_start(12)
        self._list_box.set_margin_end(12)
        scroll.set_child(self._list_box)

    def update(self, result: ScanResult):
        while (child := self._list_box.get_first_child()):
            self._list_box.remove(child)

        # Only show findings that have a fix command
        fixable = [f for f in result.findings if f.fix_command]

        if not fixable:
            row = Gtk.ListBoxRow()
            lbl = Gtk.Label(label="No automated fixes available for current findings.")
            lbl.set_margin_top(16)
            lbl.set_margin_bottom(16)
            row.set_child(lbl)
            self._list_box.append(row)
            return

        for finding in fixable:
            self._list_box.append(self._make_fix_row(finding))

    def _make_fix_row(self, finding: Finding) -> Gtk.ListBoxRow:
        row = Gtk.ListBoxRow()
        box = Gtk.Box(spacing=12)
        box.set_margin_top(10)
        box.set_margin_bottom(10)
        box.set_margin_start(12)
        box.set_margin_end(12)

        # Text column
        text_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        text_box.set_hexpand(True)

        title = Gtk.Label()
        title.set_markup(f"<b>{finding.title}</b>")
        title.set_halign(Gtk.Align.START)
        text_box.append(title)

        desc = Gtk.Label(label=finding.fix_description or "")
        desc.set_halign(Gtk.Align.START)
        desc.add_css_class("caption")
        text_box.append(desc)

        cmd = Gtk.Label(label=f"$ {finding.fix_command}")
        cmd.set_halign(Gtk.Align.START)
        cmd.add_css_class("monospace")
        cmd.add_css_class("dim-label")
        text_box.append(cmd)

        box.append(text_box)

        # Apply button
        btn = Gtk.Button(label="Apply")
        btn.add_css_class("destructive-action")
        btn.set_valign(Gtk.Align.CENTER)
        btn.connect("clicked", self._on_apply_clicked, finding, btn)
        box.append(btn)

        row.set_child(box)
        return row

    def _on_apply_clicked(self, btn, finding: Finding, button: Gtk.Button):
        """Apply fix in background thread."""
        button.set_sensitive(False)
        button.set_label("Applying…")

        action = FixAction(
            action_id=finding.engine + ":" + finding.title,
            title=finding.title,
            command=finding.fix_command,
            requires_root=True,
        )

        def run():
            success, output = self._win._app.fix_eng.apply(action)
            self._win._app.log_mgr.log_fix(
                action.action_id, action.title,
                action.command, success, output
            )
            GLib.idle_add(self._on_fix_done, success, output, button)

        threading.Thread(target=run, daemon=True).start()

    def _on_fix_done(self, success: bool, output: str, button: Gtk.Button):
        if success:
            button.set_label("✓ Applied")
            button.add_css_class("success")
        else:
            button.set_label("✗ Failed")
            button.set_sensitive(True)

        # Show output dialog
        dialog = Gtk.AlertDialog()
        dialog.set_message("Fix Result")
        dialog.set_detail(output or "(no output)")
        dialog.show(self._win)

        return False