import sys
import os
import json
import time
import win32file
import socket
import subprocess
from PyQt6.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QWidget, 
                             QSystemTrayIcon, QMenu, QPushButton, QHBoxLayout, 
                             QTabWidget, QTableWidget, QTableWidgetItem, QHeaderView,
                             QComboBox, QLabel)
from PyQt6.QtGui import QIcon, QAction, QColor
from PyQt6.QtCore import QThread, pyqtSignal, QObject

PIPE_NAME = r'\\.\pipe\SimpleEDRPipe1'
PROGRAM_DATA = os.environ.get('PROGRAMDATA', r'C:\ProgramData')
LOG_DIR = os.path.join(PROGRAM_DATA, "EdrAgent")
LOG_FILE = os.path.join(LOG_DIR, "agent.log")

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
        self.setWindowTitle("Simple EDR Dashboard")
        self.resize(850, 550)
        self.total_alerts = 0

        # Main Layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # Tabs
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)

        # Tab 1: Live Telemetry
        self.live_tab = QWidget()
        self.setup_live_tab()
        self.tabs.addTab(self.live_tab, "🔴 Live Telemetry")

        # Tab 2: Event History
        self.history_tab = QWidget()
        self.setup_history_tab()
        self.tabs.addTab(self.history_tab, "📜 Event History")

        # Footer Status Bar
        self.footer_layout = QHBoxLayout()
        self.status_label = QLabel("Daemon: 🔴 Stopped | Pipe: 🔴 Disconnected")
        self.status_label.setStyleSheet("font-weight: bold;")
        self.alerts_label = QLabel("Total Alerts: 0")
        self.hostname_label = QLabel(f"Hostname: {socket.gethostname()}")
        
        self.footer_layout.addWidget(self.status_label)
        self.footer_layout.addStretch()
        self.footer_layout.addWidget(self.alerts_label)
        self.footer_layout.addStretch()
        self.footer_layout.addWidget(self.hostname_label)
        main_layout.addLayout(self.footer_layout)

    def update_connection_status(self, pipe_connected, daemon_running):
        if pipe_connected:
            self.status_label.setText("Daemon: 🟢 Running | Pipe: 🟢 Connected")
        elif daemon_running:
            self.status_label.setText("Daemon: 🟢 Running | Pipe: 🔴 Disconnected")
        else:
            self.status_label.setText("Daemon: 🔴 Stopped | Pipe: 🔴 Disconnected")

    def apply_stylesheet(self):
        """Applies a clean, modern Dark Mode aesthetic to the dashboard."""
        self.setStyleSheet("""
            QMainWindow, QWidget {
                background-color: #1e1e2e;
                color: #cdd6f4;
                font-family: 'Segoe UI', system-ui, sans-serif;
                font-size: 13px;
            }
            QTabWidget::pane {
                border: 1px solid #313244;
                border-radius: 6px;
                background-color: #1e1e2e;
            }
            QTabBar::tab {
                background: #181825;
                color: #a6adc8;
                padding: 8px 20px;
                border: 1px solid #313244;
                border-bottom: none;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background: #313244;
                color: #cdd6f4;
                font-weight: bold;
            }
            QTableWidget {
                background-color: #181825;
                color: #cdd6f4;
                border: 1px solid #313244;
                border-radius: 6px;
                gridline-color: #313244;
                selection-background-color: #45475a;
            }
            QHeaderView::section {
                background-color: #313244;
                color: #cdd6f4;
                padding: 6px;
                border: none;
                border-right: 1px solid #1e1e2e;
                font-weight: bold;
            }
            QPushButton {
                background-color: #89b4fa;
                color: #11111b;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #b4befe;
            }
            QComboBox {
                background-color: #313244;
                color: #cdd6f4;
                border: 1px solid #45475a;
                border-radius: 4px;
                padding: 4px 8px;
            }
            QComboBox::drop-down {
                border: none;
            }
        """)

    def create_event_table(self):
        table = QTableWidget(0, 5)
        table.setHorizontalHeaderLabels(["Timestamp", "Severity", "Event Type", "Process / Path", "Details"])
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        return table

    def setup_live_tab(self):
        layout = QVBoxLayout(self.live_tab)
        
        # Filter Bar
        control_layout = QHBoxLayout()
        self.filter_dropdown = QComboBox()
        self.filter_dropdown.addItems(["All Events", "High Severity Only"])
        self.filter_dropdown.currentTextChanged.connect(self.apply_filter)
        control_layout.addWidget(QLabel("Filter:"))
        control_layout.addWidget(self.filter_dropdown)
        control_layout.addStretch()
        layout.addLayout(control_layout)

        # Telemetry Table
        self.live_table = self.create_event_table()
        layout.addWidget(self.live_table)

    def setup_history_tab(self):
        layout = QVBoxLayout(self.history_tab)
        
        btn_layout = QHBoxLayout()
        self.refresh_btn = QPushButton("🔄 Refresh History")
        self.refresh_btn.clicked.connect(self.load_history)
        btn_layout.addWidget(self.refresh_btn)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        self.history_table = self.create_event_table()
        layout.addWidget(self.history_table)
        self.load_history()

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
                        # Extract the JSON payload from Raj's log format (Timestamp | JSON)
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

            # Determine Severity
            e_type = event.get("type", "")
            if e_type in ["INSTALLER_DETECTED", "PERSISTENCE_DETECTED", "FILE_DOWNLOADED"]:
                severity = "High"
                color = QColor("#ffcccc")
            elif e_type == "NETWORK_CONNECTION":
                severity = "Medium"
                color = QColor("#cce5ff")
            else:
                severity = "Low"
                color = QColor("#ffffff")
                if e_type == "UAC_DETECTED": color = QColor("#ffffcc")

            proc_details = f"{event.get('process_name', 'N/A')} (PID: {event.get('pid', 'N/A')})"
            if 'path' in event: proc_details += f"\nPath: {event.get('path')}"

            table.setItem(row, 0, QTableWidgetItem(event.get("timestamp", "")))
            table.setItem(row, 1, QTableWidgetItem(severity))
            table.setItem(row, 2, QTableWidgetItem(e_type))
            table.setItem(row, 3, QTableWidgetItem(proc_details))
            table.setItem(row, 4, QTableWidgetItem(event.get("message", "")))

            for col in range(5):
                table.item(row, col).setBackground(color)

            table.scrollToBottom()
            if table == self.live_table:
                self.apply_filter()
        except json.JSONDecodeError:
            pass

    def apply_filter(self):
        filter_text = self.filter_dropdown.currentText()
        for row in range(self.live_table.rowCount()):
            item = self.live_table.item(row, 1) # Severity Column
            if item:
                if filter_text == "High Severity Only" and item.text() != "High":
                    self.live_table.setRowHidden(row, True)
                else:
                    self.live_table.setRowHidden(row, False)


class SystemTrayApp(QObject):
    def __init__(self, app):
        super().__init__()
        self.app = app
        self.main_window = MainWindow()

        # Try to load icon
        self.icon = QIcon("assets/guard.ico")
        if self.icon.isNull():
             self.icon = QIcon.fromTheme("security-high")

        self.tray = QSystemTrayIcon(self.icon)
        self.menu = QMenu()
        
        # Tray Status Indicators
        self.daemon_status_action = QAction("Daemon Status: 🔴 Stopped", self)
        self.daemon_status_action.setEnabled(False)
        self.menu.addAction(self.daemon_status_action)

        self.pipe_status_action = QAction("Pipe Status: 🔴 Disconnected", self)
        self.pipe_status_action.setEnabled(False)
        self.menu.addAction(self.pipe_status_action)
        
        self.menu.addSeparator()

        self.show_action = QAction("Show Dashboard")
        self.show_action.triggered.connect(self.show_dashboard)
        self.menu.addAction(self.show_action)

        self.quit_action = QAction("Exit App")
        self.quit_action.triggered.connect(self.app.quit)
        self.menu.addAction(self.quit_action)

        self.tray.setContextMenu(self.menu)
        self.tray.activated.connect(self.on_tray_click)
        self.tray.show()

        # Status Flags
        self.is_connected = False
        self.is_daemon_running = False

        # Start Pipe Listener Thread
        self.pipe_listener = PipeListener()
        self.pipe_listener.message_received.connect(self.route_message)
        self.pipe_listener.connection_status.connect(self.update_status)
        self.pipe_listener.start()

    def route_message(self, text):
        self.main_window.process_live_event(text)

    def update_status(self, connected):
        self.is_connected = connected
        
        # Check if the Windows Service is running natively
        try:
            result = subprocess.run(["sc", "query", "SimpleEDR 1"], capture_output=True, text=True, creationflags=0x08000000)
            self.is_daemon_running = "RUNNING" in result.stdout
        except Exception:
            self.is_daemon_running = False

        # Update Tray Menu Text
        if self.is_daemon_running:
            self.daemon_status_action.setText("Daemon Status: 🟢 Running")
        else:
            self.daemon_status_action.setText("Daemon Status: 🔴 Stopped")

        if connected:
            self.pipe_status_action.setText("Pipe Status: 🟢 Connected")
        else:
            self.pipe_status_action.setText("Pipe Status: 🔴 Disconnected")

        # Update Dashboard Footer
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
    
    # Show instantly unless ran silently on startup
    if "--startup" not in sys.argv:
        tray_app.show_dashboard()
        
    sys.exit(app.exec())