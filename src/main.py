"""
Guard - Main Application Entry Point
This module initializes the GTK4/Libadwaita application and wires together
the backend security engines with the frontend user interface.
"""

from __future__ import annotations
import logging
import sys

# Force GTK to use the standard Adwaita theme, bypassing Kali's custom CSS warnings
import os
os.environ["GTK_THEME"] = "Adwaita"
# gi (GObject Introspection) is the bridge between Python and the underlying C libraries.
import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

# Adw: Libadwaita. This gives our app modern GNOME styling (rounded corners, dark mode).
# Gio: GNOME Input/Output. Handles low-level system integrations like app lifecycles.
from gi.repository import Adw, Gio 

# --- Backend Core Imports ---
from src.scan_runner import ScanRunner
from src.fix_engine import FixEngine
from src.log_manager import LogManager
from src.config_manager import ConfigManager
from src.action_registry import ActionRegistry

# --- Active Engines ---
from src.engines.port_scanner import PortScanner
from src.engines.ssh_auditor import SSHAuditor
from src.engines.service_auditor import ServiceAuditor

# --- Stub Engines (Activate when implemented) ---
#from src.engines.kernel_hardening import KernelHardeningAuditor
#from src.engines.file_permission import FilePermissionAuditor
#from src.engines.user_auditor import UserAuditor

# --- Logging Configuration ---
# The format string dictates how logs look. 
# %(asctime)s: Timestamp.
# %(levelname)-8s: Severity (INFO, DEBUG), padded to exactly 8 characters for neat columns.
# %(name)s: The name of the file generating the log.
# %(message)s: The actual log message.
logging.basicConfig(
    level=logging.DEBUG, 
    format="%(asctime)s %(levelname)-8s %(name)s:%(message)s"
)

# __name__ evaluates to "__main__" if run directly, or "src.main" if imported.
# This makes it instantly clear in the log output which file produced the message.
logger = logging.getLogger(__name__)


def build_scanner() -> ScanRunner:
    """
    Factory function to initialize the ScanRunner and register all active engines.
    """
    runner = ScanRunner()
    runner.register_engine(PortScanner)
    runner.register_engine(SSHAuditor)
    runner.register_engine(ServiceAuditor)
    # Uncomment when implemented:
    # runner.register_engine(KernelHardeningAuditor)
    # runner.register_engine(FilePermissionAuditor)
    # runner.register_engine(UserAuditor)
    return runner 


class LinuxGuardApp(Adw.Application):
    """
    The main application class.
    Inheritance: This class *is an* Adw.Application, meaning it inherits all
    the standard window management and OS integration features of a GNOME app.
    """
    
    def __init__(self):
        # Call the parent Adw.Application constructor to set up the app.
        super().__init__(
            application_id="org.roaa.linuxguard",
            flags=Gio.ApplicationFlags.DEFAULT_FLAGS
        )
        
        self.scanner = build_scanner()
        self.fix_eng = FixEngine()
        self.log_mgr = LogManager()
        self.config = ConfigManager()
        self.registry = ActionRegistry()
        
        # GTK Signal System (Event-driven programming).
        # We tell the GTK framework: "When you emit the 'activate' signal, execute my _on_activate method."
        self.connect("activate", self._on_activate)

    def _on_activate(self, app):

        from src.main_window import MainWindow
        
        win = MainWindow(app)
        
        win.present()


def main():

    app = LinuxGuardApp()
    
    sys.exit(app.run(sys.argv))


# --- Execution Guard ---
# This checks if the file is being run directly from the terminal (python main.py).
# If this file is imported by another script __name__ will NOT be "__main__", and the app will not accidentally launch.
if __name__ == "__main__":
    main()