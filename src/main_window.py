# src/main_window.py
"""GTK4 application window with sidebar navigation."""
from __future__ import annotations

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk, GLib

from src.ui.overview_page import OverviewPage
from src.ui.scan_results_page import ScanResultsPage
from src.ui.hardening_page import HardeningPage
from src.ui.logs_page import LogsPage


class MainWindow(Adw.ApplicationWindow):
    """
    The main window with a left sidebar (NavigationSplitView).

    Page routing works like this:
      1. User clicks a sidebar row
      2. _on_nav_selected() is called
      3. We swap the visible child of self._stack
    """

    def __init__(self, app):
        super().__init__(application=app, title="PardusGuard")
        self.set_default_size(1100, 700)

        self._app = app
        self._last_result = None  # holds the most recent ScanResult

        self._build_ui()

    # ------------------------------------------------------------------ #
    # UI construction
    # ------------------------------------------------------------------ #

    def _build_ui(self):
        # Outer layout: header bar + content
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL) # the master container
        self.set_content(outer)

        header = Adw.HeaderBar()
        outer.append(header)

        # Title widget
        header.set_title_widget(Gtk.Label(label="PardusGuard"))

        # Scan button in header
        self._scan_btn = Gtk.Button(label="Run Scan")
        self._scan_btn.add_css_class("suggested-action")
        self._scan_btn.connect("clicked", self._on_scan_clicked)
        header.pack_start(self._scan_btn)

        # Progress bar (hidden until scanning)
        self._progress = Gtk.ProgressBar()
        self._progress.set_visible(False)
        outer.append(self._progress)

        # Navigation split view: sidebar | content
        split = Adw.NavigationSplitView()
        outer.append(split)
        split.set_vexpand(True)

        # Sidebar
        sidebar_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        sidebar_box.set_size_request(200, -1)

        nav_label = Gtk.Label(label="Navigation")
        nav_label.add_css_class("heading")
        nav_label.set_margin_top(12)
        nav_label.set_margin_bottom(8)
        nav_label.set_margin_start(12)
        nav_label.set_halign(Gtk.Align.START)
        sidebar_box.append(nav_label)

        # Sidebar list
        self._nav_list = Gtk.ListBox() # a vertical list of rows
        self._nav_list.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self._nav_list.connect("row-selected", self._on_nav_selected)
        self._nav_list.add_css_class("navigation-sidebar")
        sidebar_box.append(self._nav_list)

        sidebar_page = Adw.NavigationPage.new(sidebar_box, "Sidebar")
        split.set_sidebar(sidebar_page)

        # Content stack
        self._stack = Gtk.Stack()
        self._stack.set_transition_type(Gtk.StackTransitionType.SLIDE_UP_DOWN)
        self._stack.set_vexpand(True)
        self._stack.set_hexpand(True)

        content_page = Adw.NavigationPage.new(self._stack, "Content")
        split.set_content(content_page)

        # Create pages
        self._pages: dict[str, tuple[str, Gtk.Widget]] = {}
        self._overview_page   = OverviewPage(self)
        self._results_page    = ScanResultsPage(self)
        self._hardening_page  = HardeningPage(self)
        self._logs_page       = LogsPage(self)

        self._add_page("Overview",  "🛡  Overview",      self._overview_page)
        self._add_page("results",   "🔍 Scan Results",   self._results_page)
        self._add_page("hardening", "🔧 Hardening",      self._hardening_page)
        self._add_page("logs",      "📋 Logs",           self._logs_page)

        # Select first page
        self._nav_list.select_row(self._nav_list.get_row_at_index(0))

    def _add_page(self, page_id: str, label: str, widget: Gtk.Widget):
        """Add a page to the stack and a row to the sidebar."""
        self._stack.add_named(widget, page_id)
    
        row = Gtk.ListBoxRow()
        row_label = Gtk.Label(label=label)
        row_label.set_halign(Gtk.Align.START)
        row_label.set_margin_top(8)
        row_label.set_margin_bottom(8)
        row_label.set_margin_start(12)
        row.set_child(row_label)
        row.page_id = page_id          # stash the id on the row object
        self._nav_list.append(row)

    # ------------------------------------------------------------------ #
    # Event handlers
    # ------------------------------------------------------------------ #

    def _on_nav_selected(self, listbox, row):
        if row is None:
            return
        self._stack.set_visible_child_name(row.page_id)

    def _on_scan_clicked(self, btn):
        """Start the scan in a background thread."""
        self._scan_btn.set_sensitive(False)
        self._scan_btn.set_label("Scanning…")
        self._progress.set_visible(True)
        self._progress.set_fraction(0.0)

        import threading #  move scanning to a background thread to keep the UI responsive
        #A daemon thread will automatically be killed by the OS if the user closes the main app window
        thread = threading.Thread(target=self._run_scan_thread, daemon=True)
        thread.start()

    def _run_scan_thread(self):
        """
        Background thread: runs the scan, then hands results
        back to the GTK main thread via GLib.idle_add.

        — GTK is not thread-safe (its single-thread).
        so the backgrouns thread cannot update the progress bar directly
        """
        def progress_cb(engine_name, current, total):
            fraction = current / total
            GLib.idle_add(self._progress.set_fraction, fraction)

        result = self._app.scanner.run_all(progress_callback=progress_cb)
        GLib.idle_add(self._on_scan_complete, result)

    def _on_scan_complete(self, result):
        """Called on the GTK main thread after scanning finishes."""
        self._last_result = result

        # Log to audit database
        self._app.log_mgr.log_scan(result.score, result.label, result.findings)

        # Update all pages with fresh results
        self._overview_page.update(result)
        self._results_page.update(result)
        self._hardening_page.update(result)
        self._logs_page.refresh()

        # Reset scan button
        self._scan_btn.set_sensitive(True)
        self._scan_btn.set_label("Run Scan")
        self._progress.set_visible(False)

        # Navigate to results
        self._stack.set_visible_child_name("results")
        for i, row in enumerate(self._nav_list):
            if hasattr(row, 'page_id') and row.page_id == "results":
                self._nav_list.select_row(row)
                break

        return False  # GLib.idle_add requires False to not repeat (to removw the function from executing queue)