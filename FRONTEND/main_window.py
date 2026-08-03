import sys
import socket
import win32event
import win32api
import winerror
import qdarktheme

from PyQt6.QtWidgets import (QApplication, QToolBar, QMainWindow, QVBoxLayout, QWidget, QHBoxLayout, QTabWidget, QLabel, QPushButton)
from PyQt6.QtCore import Qt

from workers.pipe_listener import PipeListener, send_backend_command
from components.software_tab import SoftwareTab
from components.live_stream_tab import LiveStreamTab
from components.history_tab import HistoryTab
from utils.theme import apply_modern_theme

MUTEX_NAME = "Local\\EDR_Shield_Frontend_Mutex_v2"

# 1. Ask Windows for the lock and attach it to a root-level variable
APP_MUTEX = win32event.CreateMutex(None, False, MUTEX_NAME)

# 2. Check IMMEDIATELY if Windows says "Someone else already has this"
if win32api.GetLastError() == winerror.ERROR_ALREADY_EXISTS:
    print("FATAL: Another instance is already running. Exiting instantly.")
    sys.exit(0)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("EDR Agent Dashboard")
        self.resize(1000, 650)
        self.total_alerts = 0
        self.is_dark_mode = True
        
        # 1. Create a Toolbar at the top
        toolbar = QToolBar("Main Toolbar")
        self.addToolBar(toolbar)
        
        # 2. Create the Toggle Button
        self.theme_toggle_btn = QPushButton("Switch to Light Mode")
        self.theme_toggle_btn.clicked.connect(self.toggle_theme)
        
        # 3. Add the button to the Toolbar!
        toolbar.addWidget(self.theme_toggle_btn)

        # Apply Modern Dark Theme
        apply_modern_theme(self)

        # Main Layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(15, 15, 15, 15)
        main_layout.setSpacing(15)

        # Header Title
        header_label = QLabel("EDR AGENT DASHBOARD")
        header_label.setStyleSheet("font-size: 22px; font-weight: bold; color: #58a6ff; letter-spacing: 2px;")
        main_layout.addWidget(header_label)

        # Tabs
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)

        # Tab 1: Live Telemetry
        self.live_tab = LiveStreamTab()
        self.tabs.addTab(self.live_tab, " Live Stream")

        # Tab 2: Softwares
        self.softwares_tab = SoftwareTab()
        self.tabs.addTab(self.softwares_tab, "Softwares")

        # Tab 3: Event History
        self.history_tab = HistoryTab()
        self.tabs.addTab(self.history_tab, "📜 Forensic Logs")

        # Footer Status Bar
        self.footer_layout = QHBoxLayout()
        # ... add your widgets to footer_layout ...
        self.status_label = QLabel("Daemon: Stopped  |  Pipe: Disconnected")
        # self.status_label.setStyleSheet("font-weight: bold; font-size: 35px; color: #8b949e; background: #161b22; padding: 8px; border-radius: 6px;")
        self.status_label.setStyleSheet("font-weight: bold; font-size: 35px; padding: 8px; border-radius: 6px;")
        self.alerts_label = QLabel("Total Alerts: 0")
        # self.alerts_label.setStyleSheet("font-weight: bold; color: #ff7b72; background: #161b22; padding: 8px; border-radius: 6px;")
        self.alerts_label.setStyleSheet("font-weight: bold; padding: 8px; border-radius: 6px;")
        self.live_tab.alert_received.connect(self.update_alert_label)
        self.hostname_label = QLabel(f"Host: {socket.gethostname()}")
        # self.hostname_label.setStyleSheet("color: #8b949e; background: #161b22; padding: 8px; border-radius: 6px;")
        self.hostname_label.setStyleSheet("padding: 8px; border-radius: 6px;")

        # --- ADD THESE NEW LABELS ---
        self.boot_time_label = QLabel("Boot: Unknown")
        self.boot_time_label.setStyleSheet("color: #8b949e; background: #161b22; padding: 8px; border-radius: 6px;")
        
        self.users_label = QLabel("Users: 0")
        self.users_label.setStyleSheet("color: #8b949e; background: #161b22; padding: 8px; border-radius: 6px;")

        # Auto-Pilot Toggle Button
        # ---> ADD THE AUTOPILOT BUTTON HERE <---
        self.autopilot_btn = QPushButton("Auto-Pilot: OFF")
        self.autopilot_btn.setCheckable(True)
        self.autopilot_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.autopilot_btn.setStyleSheet("background-color: #30363d; color: #8b949e; padding: 8px; border-radius: 6px; font-weight: bold;")
        self.autopilot_btn.clicked.connect(self.toggle_autopilot)

        self.footer_layout.addWidget(self.status_label)
        self.footer_layout.addStretch()
        self.footer_layout.addWidget(self.boot_time_label)  # <-- NEW_boot
        self.footer_layout.addWidget(self.users_label)      #<-- NEW_switch_user
        self.footer_layout.addWidget(self.autopilot_btn)    # <-- NEW_auto-pilot button
        self.footer_layout.addWidget(self.alerts_label)
        self.footer_layout.addWidget(self.hostname_label)
        main_layout.addLayout(self.footer_layout)

        self.total_alerts = 0
        self.history_events = []
        self.history_tab.load_history()

    def update_alert_label(self, count):
        """Updates the global UI when the LiveStreamTab receives a new alert."""
        self.alerts_label.setText(f"Total Alerts: {count}")

    def toggle_theme(self):
        # Get the global application instance again
        app = QApplication.instance()
        
        if self.is_dark_mode:
            # Switch to Light Theme
            app.setStyleSheet(qdarktheme.load_stylesheet("light"))
            self.theme_toggle_btn.setText("Switch to Dark Mode")
            self.is_dark_mode = False
        else:
            # Switch to Dark Theme
            app.setStyleSheet(qdarktheme.load_stylesheet("dark"))
            self.theme_toggle_btn.setText("Switch to Light Mode")
            self.is_dark_mode = True

    def closeEvent(self, event):
        """
        When the user clicks the 'X' button on the dashboard, 
        ignore the quit command and just hide the window to the tray.
        """
        event.ignore()
        # Wipes all current rows so you only see fresh events when reopened
        if hasattr(self.live_tab, 'live_table'):
            self.live_tab.live_table.setRowCount(0)
        self.hide()

    def update_connection_status(self, pipe_connected, daemon_running):
        if pipe_connected:
            self.status_label.setText("Daemon: Running  |  Pipe: Connected")
            self.status_label.setStyleSheet("font-weight: bold; color: #3fb950; background: #161b22; padding: 8px; border-radius: 6px;")
        elif daemon_running:
            self.status_label.setText("Daemon: Running  |  Pipe: Disconnected")
            self.status_label.setStyleSheet("font-weight: bold; color: #d29922; background: #161b22; padding: 8px; border-radius: 6px;")
        else:
            self.status_label.setText("Daemon: Stopped  |  Pipe: Disconnected")
            self.status_label.setStyleSheet("font-weight: bold; color: #ff7b72; background: #161b22; padding: 8px; border-radius: 6px;")

    #switch _user and boot time update
    def update_boot_ui(self, boot_time_str):
        self.boot_time_label.setText(f"Boot: {boot_time_str}")

    def update_users_ui(self, users_list):
        user_count = len(users_list)
        formatted_users = ", ".join(users_list) if users_list else "None"
        self.users_label.setToolTip(formatted_users) # Shows names when hovering!
        self.users_label.setText(f"Users: {user_count}")
    #above in both switch and boot time update

    def process_live_event(self, json_str):
        self.live_tab.add_row_to_table(json_str)


    # --- NEW: Auto-Pilot Toggle Handler ---
    def toggle_autopilot(self, checked):
        if checked:
            self.autopilot_btn.setText("Auto-Pilot: ON (ACTIVE)")
            self.autopilot_btn.setStyleSheet("background-color: #da3633; color: #ffffff; padding: 8px; border-radius: 6px; font-weight: bold; border: 1px solid #ff7b72;")
            send_backend_command("TOGGLE_AUTOPILOT", pid="ON")
        else:
            self.autopilot_btn.setText("Auto-Pilot: OFF")
            self.autopilot_btn.setStyleSheet("background-color: #30363d; color: #8b949e; padding: 8px; border-radius: 6px; font-weight: bold;")
            send_backend_command("TOGGLE_AUTOPILOT", pid="OFF")