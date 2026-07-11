import sys
import os
import json
import time
import win32file
import socket
import subprocess
import ctypes
from PyQt6.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QWidget, 
                             QSystemTrayIcon, QMenu, QPushButton, QHBoxLayout, 
                             QTabWidget, QTableWidget, QTableWidgetItem, QHeaderView,
                             QComboBox, QLabel, QStyle)
from PyQt6.QtGui import QIcon, QAction, QColor, QFont
from PyQt6.QtCore import QThread, pyqtSignal, QObject, Qt, QTimer


# SPECIFIC UPDATE: Pipe name updated to SimpleEDRPipe1
PIPE_NAME = r'\\.\pipe\SimpleEDRPipe1'
PROGRAM_DATA = os.environ.get('PROGRAMDATA', r'C:\ProgramData')
LOG_DIR = os.path.join(PROGRAM_DATA, "EdrAgent")
LOG_FILE = os.path.join(LOG_DIR, "agent.log")

def get_resource_path(relative_path):
    """ Safely get absolute path to resource, works for dev and for PyInstaller """
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

class PipeListener(QThread):
    message_received = pyqtSignal(str)
    connection_status = pyqtSignal(bool)

    def run(self):
        while True:
            try:
                handle = win32file.CreateFile(
                    PIPE_NAME, win32file.GENERIC_READ, 0, None, win32file.OPEN_EXISTING, 0, None
                )
                self.connection_status.emit(True)
                
                buffer = ""
                while True:
                    resp = win32file.ReadFile(handle, 4096)
                    if resp[0] == 0:
                        chunk = resp[1].decode('utf-8')
                        buffer += chunk
                        while "\n" in buffer:
                            line, buffer = buffer.split("\n", 1)
                            if line.strip():
                                self.message_received.emit(line)
            except Exception:
                self.connection_status.emit(False)
                time.sleep(3)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Shield EDR | Enterprise Dashboard")
        self.resize(1000, 650)
        self.total_alerts = 0

        # Apply Modern Dark Theme
        self.apply_modern_theme()

        # Main Layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(15, 15, 15, 15)
        main_layout.setSpacing(15)

        # Header Title
        header_label = QLabel("ENDPOINT SENSOR DASHBOARD")
        header_label.setStyleSheet("font-size: 22px; font-weight: bold; color: #58a6ff; letter-spacing: 2px;")
        main_layout.addWidget(header_label)

        # Tabs
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)

        # Tab 1: Live Telemetry
        self.live_tab = QWidget()
        self.setup_live_tab()
        self.tabs.addTab(self.live_tab, "🔴 Live Stream")

        # Tab 2: Softwares
        self.softwares_tab = QWidget()
        self.setup_softwares_tab()
        self.tabs.addTab(self.softwares_tab, "Softwares")

        # Tab 3: Event History
        self.history_tab = QWidget()
        self.setup_history_tab()
        self.tabs.addTab(self.history_tab, "📜 Forensic Logs")

        # Footer Status Bar
        self.footer_layout = QHBoxLayout()
        self.status_label = QLabel("Daemon: 🔴 Stopped  |  Pipe: 🔴 Disconnected")
        self.status_label.setStyleSheet("font-weight: bold; color: #8b949e; background: #161b22; padding: 8px; border-radius: 6px;")
        self.alerts_label = QLabel("Total Alerts: 0")
        self.alerts_label.setStyleSheet("font-weight: bold; color: #ff7b72; background: #161b22; padding: 8px; border-radius: 6px;")
        self.hostname_label = QLabel(f"Host: {socket.gethostname()}")
        self.hostname_label.setStyleSheet("color: #8b949e; background: #161b22; padding: 8px; border-radius: 6px;")
        
        self.footer_layout.addWidget(self.status_label)
        self.footer_layout.addStretch()
        self.footer_layout.addWidget(self.alerts_label)
        self.footer_layout.addWidget(self.hostname_label)
        main_layout.addLayout(self.footer_layout)

    # SPECIFIC UPDATE: Intercepting the window close event to hide instead of exit
    def closeEvent(self, event):
        """
        When the user clicks the 'X' button on the dashboard, 
        ignore the quit command and just hide the window to the tray.
        """
        event.ignore()
        self.hide()

    def apply_modern_theme(self):
        """Applies a highly polished, VS Code / GitHub style dark mode."""
        self.setStyleSheet("""
            QMainWindow, QWidget {
                background-color: #0d1117;
                color: #c9d1d9;
                font-family: 'Segoe UI', system-ui, sans-serif;
                font-size: 13px;
            }
            QTabWidget::pane {
                border: 1px solid #30363d;
                border-radius: 8px;
                background-color: #161b22;
                margin-top: -1px;
            }
            QTabBar::tab {
                background: #0d1117;
                color: #8b949e;
                padding: 10px 24px;
                border: 1px solid transparent;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                font-weight: bold;
            }
            QTabBar::tab:selected {
                background: #161b22;
                color: #58a6ff;
                border: 1px solid #30363d;
                border-bottom-color: #161b22;
            }
            QTabBar::tab:hover:!selected {
                background: #21262d;
                color: #c9d1d9;
            }
            QTableWidget {
                background-color: #0d1117;
                color: #c9d1d9;
                border: none;
                gridline-color: #30363d;
                selection-background-color: #1f6feb;
                border-radius: 8px;
            }
            QHeaderView::section {
                background-color: #161b22;
                color: #8b949e;
                padding: 10px;
                border: none;
                border-right: 1px solid #30363d;
                border-bottom: 1px solid #30363d;
                font-weight: bold;
                text-transform: uppercase;
            }
            QPushButton {
                background-color: #238636;
                color: #ffffff;
                border: 1px solid rgba(240, 246, 252, 0.1);
                padding: 8px 20px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2ea043;
            }
            QPushButton:pressed {
                background-color: #1a6428;
            }
            QComboBox {
                background-color: #161b22;
                color: #c9d1d9;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 6px 12px;
            }
            QComboBox::drop-down {
                border: none;
            }
            QComboBox QAbstractItemView {
                background-color: #161b22;
                border: 1px solid #30363d;
                selection-background-color: #1f6feb;
            }
        """)

    def update_connection_status(self, pipe_connected, daemon_running):
        if pipe_connected:
            self.status_label.setText("Daemon: 🟢 Running  |  Pipe: 🟢 Connected")
            self.status_label.setStyleSheet("font-weight: bold; color: #3fb950; background: #161b22; padding: 8px; border-radius: 6px;")
        elif daemon_running:
            self.status_label.setText("Daemon: 🟢 Running  |  Pipe: 🔴 Disconnected")
            self.status_label.setStyleSheet("font-weight: bold; color: #d29922; background: #161b22; padding: 8px; border-radius: 6px;")
        else:
            self.status_label.setText("Daemon: 🔴 Stopped  |  Pipe: 🔴 Disconnected")
            self.status_label.setStyleSheet("font-weight: bold; color: #ff7b72; background: #161b22; padding: 8px; border-radius: 6px;")

    def create_event_table(self):
        table = QTableWidget(0, 5)
        table.setHorizontalHeaderLabels(["TIMESTAMP", "SEVERITY", "EVENT TYPE", "PROCESS / PATH", "DETAILS"])
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setAlternatingRowColors(True)
        table.setShowGrid(False)
        return table

    def setup_live_tab(self):
        layout = QVBoxLayout(self.live_tab)
        layout.setContentsMargins(10, 10, 10, 10)
        
        control_layout = QHBoxLayout()
        self.filter_dropdown = QComboBox()
        self.filter_dropdown.addItems(["All Events", "High Severity Only"])
        self.filter_dropdown.currentTextChanged.connect(self.apply_filter)
        control_layout.addWidget(QLabel("FILTER EVENTS:"))
        control_layout.addWidget(self.filter_dropdown)
        control_layout.addStretch()
        layout.addLayout(control_layout)

        self.live_table = self.create_event_table()
        layout.addWidget(self.live_table)

    def setup_history_tab(self):
        layout = QVBoxLayout(self.history_tab)
        layout.setContentsMargins(10, 10, 10, 10)
        
        btn_layout = QHBoxLayout()
        self.refresh_btn = QPushButton("🔄 Refresh Log History")
        self.refresh_btn.clicked.connect(self.load_history)
        btn_layout.addWidget(self.refresh_btn)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        self.history_table = self.create_event_table()
        layout.addWidget(self.history_table)
        self.load_history()

    def setup_softwares_tab(self):
        # Assuming self.softwares_tab is already initialized in your main __init__
        layout = QVBoxLayout(self.softwares_tab)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Add a refresh button layout at the top, matching the history tab style
        btn_layout = QHBoxLayout()
        self.refresh_softwares_btn = QPushButton("🔄 Refresh Installed Software")
        self.refresh_softwares_btn.clicked.connect(self.load_softwares)
        btn_layout.addWidget(self.refresh_softwares_btn)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        # Initialize the table specifically for the 5 software attributes
        self.softwares_table = QTableWidget(0, 5)
        self.softwares_table.setHorizontalHeaderLabels([
            "Display Name", 
            "Version", 
            "Publisher", 
            "Install Location", 
            "Install Date"
        ])
        
        # Make the table look clean by stretching headers appropriately
        from PyQt6.QtWidgets import QHeaderView # Ensure this is imported at the top
        self.softwares_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch) # Name gets most space
        self.softwares_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.softwares_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.softwares_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.softwares_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        
        layout.addWidget(self.softwares_table)
        
        # Trigger initial load
        self.load_softwares()

    def load_softwares(self):
        """Parses the JSON string from the backend and populates the Softwares table."""
        try:
            # THIS is where 'event' comes from. It parses the JSON string into a Python dictionary.
            # event = json.loads(json_str)
            
            # Clear the table before loading the new list so it doesn't duplicate endlessly
            self.softwares_table.setRowCount(0)
            
            # Grab the list safely. If it's missing, default to an empty list [].
            # installed_softwares = event.get("software_list", [])
            
            # for software in installed_softwares:
            #     row = self.softwares_table.rowCount()
            #     self.softwares_table.insertRow(row)
                
            #     self.softwares_table.setItem(row, 0, QTableWidgetItem(software.get("display_name", "N/A")))
            #     self.softwares_table.setItem(row, 1, QTableWidgetItem(software.get("version", "N/A")))
            #     self.softwares_table.setItem(row, 2, QTableWidgetItem(software.get("publisher", "N/A")))
            #     self.softwares_table.setItem(row, 3, QTableWidgetItem(software.get("install_location", "N/A")))
            #     self.softwares_table.setItem(row, 4, QTableWidgetItem(software.get("install_date", "N/A")))
                
        except json.JSONDecodeError as e:
            print(f"Failed to parse software JSON: {e}")
        

    def process_live_event(self, json_str):
        self.add_row_to_table(self.live_table, json_str)

    def load_history(self):
        self.history_table.setRowCount(0)
        if not os.path.exists(LOG_FILE):
            return
        try:
            with open(LOG_FILE, 'r') as f:
                for line in f:
                    if " | " in line:
                        json_str = line.split(" | ", 1)[1]
                        self.add_row_to_table(self.history_table, json_str)
                    elif line.startswith("{"):
                        self.add_row_to_table(self.history_table, line)
        except Exception as e:
            print(f"Error loading history: {e}")

    def add_row_to_table(self, table, text):
        try:
            event = json.loads(text)
            self.total_alerts += 1
            self.alerts_label.setText(f"Total Alerts: {self.total_alerts}")

            row = table.rowCount()
            table.insertRow(row)

            # Modern Enterprise Colors (Subtle backgrounds, bright text)
            e_type = event.get("type", "")
            if e_type in ["INSTALLER_DETECTED", "PERSISTENCE_DETECTED", "DOWNLOAD_DETECTED"]:
                severity = "High"
                bg_color = QColor("#490202")  # Deep red background
                text_color = QColor("#ff7b72") # Bright red text
            elif e_type == "NETWORK_CONNECTION":
                severity = "Medium"
                bg_color = QColor("#0a3069")  # Deep blue background
                text_color = QColor("#79c0ff") # Bright blue text
            else:
                severity = "Low"
                bg_color = QColor("#0d1117")  # Standard dark
                text_color = QColor("#c9d1d9")
                if e_type == "UAC_DETECTED": 
                    bg_color = QColor("#3d3301") # Deep yellow
                    text_color = QColor("#e3b341")

            proc_details = f"{event.get('process_name', 'N/A')} (PID: {event.get('pid', 'N/A')})"
            if 'path' in event: proc_details += f"\nPath: {event.get('path')}"

            items = [
                QTableWidgetItem(event.get("timestamp", "")),
                QTableWidgetItem(severity),
                QTableWidgetItem(e_type),
                QTableWidgetItem(proc_details),
                QTableWidgetItem(event.get("message", ""))
            ]

            for col, item in enumerate(items):
                item.setBackground(bg_color)
                item.setForeground(text_color)
                if col in [1, 2]:
                    font = QFont()
                    font.setBold(True)
                    item.setFont(font)
                table.setItem(row, col, item)

            table.scrollToBottom()
            if table == self.live_table:
                self.apply_filter()
        except json.JSONDecodeError:
            pass

    def apply_filter(self):
        filter_text = self.filter_dropdown.currentText()
        for row in range(self.live_table.rowCount()):
            item = self.live_table.item(row, 1)
            if item:
                if filter_text == "High Severity Only" and item.text() != "High":
                    self.live_table.setRowHidden(row, True)
                else:
                    self.live_table.setRowHidden(row, False)

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

        icon_path = get_resource_path(os.path.join("Assets", "guard.ico"))
        if os.path.exists(icon_path):
            self.icon = QIcon(icon_path)
        else:
            self.icon = self.app.style().standardIcon(QStyle.StandardPixmap.SP_ComputerIcon)
        
        self.app.setWindowIcon(self.icon)
        self.tray.setIcon(self.icon)
        self.tray.setToolTip("Shield EDR Engine")
        
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

        # Added Explicit Exit Action for the Tray
        self.quit_action = QAction("Exit EDR Tray")
        self.quit_action.triggered.connect(self.app.quit)
        self.menu.addAction(self.quit_action)

        self.tray.setContextMenu(self.menu)
        self.tray.activated.connect(self.on_tray_click)
        self.tray.show()

        self.is_connected = False
        self.is_daemon_running = False

        self.status_timer = QTimer()
        self.status_timer.timeout.connect(self.poll_daemon_status)
        self.status_timer.start(2000)

        self.pipe_listener = PipeListener()
        self.pipe_listener.message_received.connect(self.route_message)
        self.pipe_listener.connection_status.connect(self.update_pipe_status)
        self.pipe_listener.start()

    def route_message(self, text):
        self.main_window.process_live_event(text)

    def poll_daemon_status(self):
        """Dynamically checks if the backend daemon is alive."""
        try:
            # SPECIFIC UPDATE: Checking for "SimpleEDR1"
            svc_result = subprocess.run(["sc", "query", "SimpleEDR1"], capture_output=True, text=True, creationflags=0x08000000)
            svc_running = "RUNNING" in svc_result.stdout
            
            # Fallback: Task manager check
            task_result = subprocess.run(["tasklist", "/FI", "IMAGENAME eq daemon.exe"], capture_output=True, text=True, creationflags=0x08000000)
            proc_running = "daemon.exe" in task_result.stdout

            self.is_daemon_running = svc_running or proc_running
        except Exception:
            self.is_daemon_running = False
            
        self.refresh_ui()

    def update_pipe_status(self, connected):
        self.is_connected = connected
        self.refresh_ui()

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
    
    # CRITICAL FIX: Ensures that closing the Dashboard window does not kill the app
    app.setQuitOnLastWindowClosed(False)
    
    tray_app = SystemTrayApp(app)
    
    # IMPORTANT: The installer should add a registry key that launches "gui.exe --startup" 
    # to HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    if "--startup" not in sys.argv:
        tray_app.show_dashboard()
        
    sys.exit(app.exec())