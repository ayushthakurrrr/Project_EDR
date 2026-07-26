import sys
import os
import json
import ctypes
import subprocess

from PyQt6.QtWidgets import QApplication, QSystemTrayIcon, QMenu
from PyQt6.QtCore import QObject, QTimer
from PyQt6.QtGui import QIcon, QAction

from main_window import MainWindow
from workers.pipe_listener import PipeListener
from workers.pipe_listener import send_backend_command
from utils.helper_functions import get_resource_path

PIPE_NAME = r"\\.\pipe\SimpleEDRPipe1"

class SystemTrayApp(QObject):
    def __init__(self, app):
        super().__init__()
        self.app = app
        
        try:
            myappid = 'devsecops.simpleedr.dashboard.1.0'
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
        except Exception:
            pass

        self.main_window = MainWindow()
        self.tray = QSystemTrayIcon(self.app)
        self.tray.setToolTip("EDR Guard")
        
        # Safely get the icon path
        icon_path = get_resource_path(os.path.join("assets", "guard.ico"))
        
        if os.path.exists(icon_path):
            guard_icon = QIcon(icon_path)
            self.tray.setIcon(guard_icon)
            self.app.setWindowIcon(guard_icon)
        else:
            self.tray.setIcon(app.style().standardIcon(app.style().StandardPixmap.SP_ComputerIcon))
        
        # --- Context Menu Setup ---
        self.menu = QMenu()

        self.daemon_status_action = QAction("Daemon: 🔴 Stopped", self)
        self.daemon_status_action.setEnabled(False)
        self.menu.addAction(self.daemon_status_action)

        self.pipe_status_action = QAction("Pipe: 🔴 Disconnected", self)
        self.pipe_status_action.setEnabled(False)
        self.menu.addAction(self.pipe_status_action)
        
        self.menu.addSeparator()

        self.show_action = QAction("Open Dashboard")
        self.show_action.triggered.connect(self.show_dashboard)
        self.menu.addAction(self.show_action)

        self.quit_action = QAction("Exit EDR Tray")
        self.quit_action.triggered.connect(self.app.quit)
        self.menu.addAction(self.quit_action)

        self.tray.setContextMenu(self.menu)
        self.tray.activated.connect(self.on_tray_click)
        self.tray.show()

        # --- State Management ---
        self.is_connected = False
        self.is_daemon_running = False

        self.status_timer = QTimer()
        self.status_timer.timeout.connect(self.poll_daemon_status)
        self.status_timer.start(2000)

        # --- Worker Setup ---
        self.pipe_listener = PipeListener(PIPE_NAME)
        self.pipe_listener.message_received.connect(self.route_message)
        self.pipe_listener.connection_status.connect(self.update_pipe_status)
        
        # Wire the software list signal directly to the MainWindow's handler
        self.pipe_listener.software_list_received.connect(self.main_window.softwares_tab.load_softwares)
        self.pipe_listener.start()

    def route_message(self, text):
        """Processes live events and routes them to the MainWindow."""
        try:
            event = json.loads(text)
            event_type = event.get("type", "")

            # Route specialized events
            if event_type == "SYSTEM_BOOT_INFO":
                boot_time = event.get("boot_time", "Unknown")
                self.main_window.update_boot_ui(boot_time)
                
            elif event_type in ("USER_SESSION_STARTED", "USER_SESSION_ENDED"):
                active_users = event.get("active_users", [])
                self.main_window.update_users_ui(active_users)

            # Route ALL events (including boot/user info) to the Live Stream tab
            self.main_window.process_live_event(text)

        except json.JSONDecodeError:
            print(f"Received malformed text over the pipe: {text}")

    def poll_daemon_status(self):
        """Dynamically checks if the backend daemon is alive."""
        try:
            svc_result = subprocess.run(["sc", "query", "SimpleEDR1"], capture_output=True, text=True, creationflags=0x08000000)
            svc_running = "RUNNING" in svc_result.stdout
            
            task_result = subprocess.run(["tasklist", "/FI", "IMAGENAME eq EDRAgentSERVICE.exe"], capture_output=True, text=True, creationflags=0x08000000)
            proc_running = "EDRAgentSERVICE.exe" in task_result.stdout

            self.is_daemon_running = svc_running or proc_running
        except Exception:
            self.is_daemon_running = False
            
        self.refresh_ui()

    def update_pipe_status(self, connected):
        self.is_connected = connected
        self.refresh_ui()

        # Automatic First Refresh Logic
        if connected and not getattr(self, '_initial_refresh_done', False):
            self._initial_refresh_done = True
            print("[GUI] Pipe connected. Requesting initial software list...")
            send_backend_command("REFRESH_SOFTWARE")

    def refresh_ui(self):
        if self.is_daemon_running:
            self.daemon_status_action.setText("Daemon: 🟢 Running")
        else:
            self.daemon_status_action.setText("Daemon: 🔴 Stopped")

        if self.is_connected:
            self.pipe_status_action.setText("Pipe: 🟢 Connected")
        else:
            self.pipe_status_action.setText("Pipe: 🔴 Disconnected")

        self.main_window.update_connection_status(self.is_connected, self.is_daemon_running)

    def on_tray_click(self, reason):
        if reason == QSystemTrayIcon.ActivationReason.Trigger:
            if self.main_window.isHidden():
                self.show_dashboard()
            else:
                self.main_window.hide()

    def show_dashboard(self):
        self.main_window.show()
        self.main_window.activateWindow()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)
    
    tray_app = SystemTrayApp(app)
    
    if "--startup" not in sys.argv:
        tray_app.show_dashboard()
        
    sys.exit(app.exec())