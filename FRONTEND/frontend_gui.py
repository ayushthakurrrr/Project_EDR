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
                             QComboBox, QLabel, QStyle, QFrame, QTextEdit, QSplitter)
from PyQt6.QtGui import QIcon, QAction, QColor, QFont
from PyQt6.QtCore import QThread, pyqtSignal, QObject, Qt, QTimer


# SPECIFIC UPDATE: Pipe name updated to SimpleEDRPipe1
PIPE_NAME = r'\\.\pipe\SimpleEDRPipe1'
PROGRAM_DATA = os.environ.get('PROGRAMDATA', r'C:\ProgramData')
LOG_DIR = os.path.join(PROGRAM_DATA, "EdrAgent")
# LOG_FILE = os.path.join(LOG_DIR, "agent.log")check now?check plz check plz once more once more

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
        self.tabs.addTab(self.live_tab, " Live Stream")

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
        # ... add your widgets to footer_layout ...
        self.status_label = QLabel("Daemon: Stopped  |  Pipe: Disconnected")
        self.status_label.setStyleSheet("font-weight: bold; font-size: 35px; color: #8b949e; background: #161b22; padding: 8px; border-radius: 6px;")
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
        # Wipes all current rows so you only see fresh events when reopened
        if hasattr(self, 'live_table'):
            self.live_table.setRowCount(0)
        # --
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
            self.status_label.setText("Daemon: Running  |  Pipe: Connected")
            self.status_label.setStyleSheet("font-weight: bold; color: #3fb950; background: #161b22; padding: 8px; border-radius: 6px;")
        elif daemon_running:
            self.status_label.setText("Daemon: Running  |  Pipe: Disconnected")
            self.status_label.setStyleSheet("font-weight: bold; color: #d29922; background: #161b22; padding: 8px; border-radius: 6px;")
        else:
            self.status_label.setText("Daemon: Stopped  |  Pipe: Disconnected")
            self.status_label.setStyleSheet("font-weight: bold; color: #ff7b72; background: #161b22; padding: 8px; border-radius: 6px;")

    def create_event_table(self):
        table = QTableWidget(0, 5)
        table.setHorizontalHeaderLabels(["TIMESTAMP", "SEVERITY", "EVENT TYPE", "PROCESS / PATH", "DETAILS"])
        
        # --- HORIZONTAL ---
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        table.horizontalHeader().setStretchLastSection(True)
        table.setColumnWidth(0, 150)
        table.setColumnWidth(1, 80)
        table.setColumnWidth(2, 180)
        table.setColumnWidth(3, 250)

        # --- VERTICAL (Fixes Cropping & S.No visibility) ---
        table.verticalHeader().setVisible(True) # Show S.No
        table.verticalHeader().setDefaultSectionSize(40) # Add breathing room for icons
        table.verticalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Fixed) 
        
        table.setWordWrap(True)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setAlternatingRowColors(True)
        table.setShowGrid(False)
        return table

    def setup_live_tab(self):
        layout = QVBoxLayout(self.live_tab)
        layout.setContentsMargins(10, 10, 10, 10)
        
        control_layout = QHBoxLayout()
        self.filter_dropdown = QComboBox()
        self.filter_dropdown.addItems(["All Events", "High Severity", "Medium Severity", "Low Severity"])
        self.filter_dropdown.currentTextChanged.connect(self.apply_filter)
        control_layout.addWidget(QLabel("FILTER EVENTS:"))
        control_layout.addWidget(self.filter_dropdown)
        control_layout.addStretch()
        layout.addLayout(control_layout)

        self.live_table = self.create_event_table()
        self.live_table.itemClicked.connect(self.show_row_details)

        # --- Build the Details Terminal Pane ---
        self.live_terminal_frame = QFrame()
        self.live_terminal_frame.setStyleSheet("""
            QFrame {
                background-color: #0d1117; 
                border: 1px solid #30363d; 
                border-radius: 5px;
            }
        """)
        
        terminal_layout = QVBoxLayout(self.live_terminal_frame)
        terminal_layout.setContentsMargins(5, 5, 5, 5)

        # Top bar for the Close Button
        close_btn_layout = QHBoxLayout()
        close_btn_layout.addStretch()
        
        # We use a mathematical multiplication sign '×' because it is perfectly symmetrical,
        # unlike a standard letter 'X' which is sometimes slightly taller than it is wide.
        self.close_terminal_btn = QPushButton("×") 
        
        # Lock the size to a perfect square
        self.close_terminal_btn.setFixedSize(24, 24)
        
        self.close_terminal_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        
        # The Master CSS
        self.close_terminal_btn.setStyleSheet("""
            QPushButton { 
                background-color: #21262d; 
                color: #c9d1d9;            
                border: 1px solid #30363d; 
                border-radius: 12px;       
                font-family: Arial, sans-serif;
                font-size: 14px;           /* Reduced slightly to guarantee fit */
                font-weight: 900;          
                padding: 0px;              /* THE FIX: Ignore global padding */
                margin: 0px;      /* Nudges the '×' up just a pixel so it is perfectly centered */
            } 
            QPushButton:hover { 
                background-color: #da3633; /* Danger Red */
                color: #ffffff;            /* Pure white cross */
                border: 1px solid #da3633;
            }
            QPushButton:pressed {
                background-color: #b32d2a; /* Slightly darker red when actually clicked */
            }
        """)
        self.close_terminal_btn.clicked.connect(self.live_terminal_frame.hide)

        close_btn_layout.addWidget(self.close_terminal_btn)

        self.live_terminal_text = QTextEdit()
        self.live_terminal_text.setReadOnly(True)
        # REMOVED: setFixedHeight(180). We want the splitter to control the height dynamically!
        self.live_terminal_text.setStyleSheet("""
            color: #79c0ff; 
            font-family: Consolas, monospace; 
            font-size: 13px; 
            border: none;
        """)

        terminal_layout.addLayout(close_btn_layout)
        terminal_layout.addWidget(self.live_terminal_text)

        # --- NEW: Assemble the Splitter ---
        # The QSplitter handles the draggable dividing line between the two widgets
        self.main_splitter = QSplitter(Qt.Orientation.Vertical)
        self.main_splitter.addWidget(self.live_table)
        self.main_splitter.addWidget(self.live_terminal_frame)
        
        # Tell the splitter how to share the space by default (e.g., Table 75%, Terminal 25%)
        self.main_splitter.setSizes([750, 250])
        
        # Add the splitter to the main layout instead of adding the table and frame separately
        layout.addWidget(self.main_splitter)
        
        self.live_terminal_frame.hide()
        
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
        self.history_table.itemClicked.connect(self.show_row_details)

        # --- Build the History Terminal Pane ---
        self.history_terminal_frame = QFrame()
        self.history_terminal_frame.setStyleSheet("QFrame { background-color: #0d1117; border: 1px solid #30363d; border-radius: 5px; }")
        
        terminal_layout = QVBoxLayout(self.history_terminal_frame)
        terminal_layout.setContentsMargins(5, 5, 5, 5)

        close_btn_layout = QHBoxLayout()
        close_btn_layout.addStretch()
        
        self.close_history_btn = QPushButton("×") 
        self.close_history_btn.setFixedSize(24, 24)
        self.close_history_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.close_history_btn.setStyleSheet("""
            QPushButton { background-color: #21262d; color: #c9d1d9; border: 1px solid #30363d; border-radius: 12px; font-family: 'Segoe UI', Arial, sans-serif; font-size: 16px; font-weight: bold; padding-bottom: 2px; } 
            QPushButton:hover { background-color: #da3633; color: #ffffff; border: 1px solid #da3633; }
            QPushButton:pressed { background-color: #b32d2a; }
        """)
        self.close_history_btn.clicked.connect(self.history_terminal_frame.hide)
        close_btn_layout.addWidget(self.close_history_btn)

        self.history_terminal_text = QTextEdit()
        self.history_terminal_text.setReadOnly(True)
        self.history_terminal_text.setStyleSheet("color: #79c0ff; font-family: Consolas, monospace; font-size: 13px; border: none;")

        terminal_layout.addLayout(close_btn_layout)
        terminal_layout.addWidget(self.history_terminal_text)

        # --- Splitter Setup ---
        self.history_splitter = QSplitter(Qt.Orientation.Vertical)
        self.history_splitter.addWidget(self.history_table)
        self.history_splitter.addWidget(self.history_terminal_frame)
        self.history_splitter.setSizes([750, 250])
        
        layout.addWidget(self.history_splitter)
        
        self.history_terminal_frame.hide()
        self.load_history()

    def setup_softwares_tab(self):
        layout = QVBoxLayout(self.softwares_tab)
        layout.setContentsMargins(10, 10, 10, 10)
        
        btn_layout = QHBoxLayout()
        self.refresh_softwares_btn = QPushButton("🔄 Refresh Installed Software")
        self.refresh_softwares_btn.setEnabled(False) 
        btn_layout.addWidget(self.refresh_softwares_btn)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        self.softwares_table = QTableWidget(0, 5)
        self.softwares_table.setHorizontalHeaderLabels(["Display Name", "Version", "Publisher", "Install Location", "Install Date"])
        
        # --- HORIZONTAL ADJUSTMENT ---
        self.softwares_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.softwares_table.horizontalHeader().setStretchLastSection(True)
        
        self.softwares_table.setColumnWidth(0, 250)  # Display Name
        self.softwares_table.setColumnWidth(1, 120)  # Version
        self.softwares_table.setColumnWidth(2, 180)  # Publisher
        self.softwares_table.setColumnWidth(3, 300)  # Install Location
        # Column 4 (Install Date) will automatically fill the remaining space
        
        self.softwares_table.itemClicked.connect(self.show_row_details)

        # --- Build the Software Terminal Pane ---
        self.software_terminal_frame = QFrame()
        self.software_terminal_frame.setStyleSheet("QFrame { background-color: #0d1117; border: 1px solid #30363d; border-radius: 5px; }")
        
        terminal_layout = QVBoxLayout(self.software_terminal_frame)
        terminal_layout.setContentsMargins(5, 5, 5, 5)

        close_btn_layout = QHBoxLayout()
        close_btn_layout.addStretch()
        
        self.close_software_btn = QPushButton("×") 
        self.close_software_btn.setFixedSize(24, 24)
        self.close_software_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.close_software_btn.setStyleSheet("""
            QPushButton { background-color: #21262d; color: #c9d1d9; border: 1px solid #30363d; border-radius: 12px; font-family: 'Segoe UI', Arial, sans-serif; font-size: 16px; font-weight: bold; padding-bottom: 2px; } 
            QPushButton:hover { background-color: #da3633; color: #ffffff; border: 1px solid #da3633; }
            QPushButton:pressed { background-color: #b32d2a; }
        """)
        self.close_software_btn.clicked.connect(self.software_terminal_frame.hide)
        close_btn_layout.addWidget(self.close_software_btn)

        self.software_terminal_text = QTextEdit()
        self.software_terminal_text.setReadOnly(True)
        self.software_terminal_text.setStyleSheet("color: #79c0ff; font-family: Consolas, monospace; font-size: 13px; border: none;")

        terminal_layout.addLayout(close_btn_layout)
        terminal_layout.addWidget(self.software_terminal_text)

        # --- Splitter Setup ---
        self.software_splitter = QSplitter(Qt.Orientation.Vertical)
        self.software_splitter.addWidget(self.softwares_table)
        self.software_splitter.addWidget(self.software_terminal_frame)
        self.software_splitter.setSizes([750, 250])
        
        layout.addWidget(self.software_splitter)
        self.software_terminal_frame.hide()

    def load_softwares(self, json_str):
        """Parses the JSON string from the backend and populates the Softwares table."""
        try:
            # 1. Parse the incoming string from the Named Pipe into a Python dictionary
            event = json.loads(json_str)
            
            # 2. Clear the table before loading the new list so it doesn't duplicate endlessly
            self.softwares_table.setRowCount(0)
            
            # 3. Grab the list safely. If it's missing, default to an empty list [].
            installed_softwares = event.get("software_list", [])
            # print(installed_softwares)
            
            # 4. Loop through the list and populate the UI table
            # Inside your load_softwares function:
            for software in installed_softwares:
                row = self.softwares_table.rowCount()
                self.softwares_table.insertRow(row)
                
                # --- NEW: Create the first item and inject the raw data ---
                display_name_item = QTableWidgetItem(software.get("display_name", "N/A"))
                # Dump the specific software dictionary back to a JSON string and save it to the row
                display_name_item.setData(Qt.ItemDataRole.UserRole, json.dumps(software))
                
                self.softwares_table.setItem(row, 0, display_name_item)
                
                # The rest of your columns remain the same
                self.softwares_table.setItem(row, 1, QTableWidgetItem(software.get("version", "N/A")))
                self.softwares_table.setItem(row, 2, QTableWidgetItem(software.get("publisher", "N/A")))
                self.softwares_table.setItem(row, 3, QTableWidgetItem(software.get("install_location", "N/A")))
                # --- INSTALL DATE FORMATTING LOGIC ---
                raw_date = software.get("install_date", "")
                display_date = "N/A"
                
                if raw_date:
                    # Windows registry dates are often YYYYMMDD (exactly 8 digits)
                    if len(raw_date) == 8 and raw_date.isdigit():
                        display_date = f"{raw_date[:4]}-{raw_date[4:6]}-{raw_date[6:]}"
                    else:
                        display_date = raw_date # Keep as-is if it's already formatted

                self.softwares_table.setItem(row, 4, QTableWidgetItem(display_date))
                
        except json.JSONDecodeError as e:
            print(f"Failed to parse software JSON: {e}")        

    def process_live_event(self, json_str):
        self.add_row_to_table(self.live_table, json_str)

    # def load_history(self):
    #     self.history_table.setRowCount(0)
    #     if not os.path.exists(LOG_FILE):
    #         return
    #     try:
    #         with open(LOG_FILE, 'r') as f:
    #             for line in f:
    #                 if " | " in line:
    #                     json_str = line.split(" | ", 1)[1]
    #                     self.add_row_to_table(self.history_table, json_str)
    #                 elif line.startswith("{"):
    #                     self.add_row_to_table(self.history_table, line)
    #     except Exception as e:
    #         print(f"Error loading history: {e}")
    def load_history(self):
        """Dynamically finds and loads the most recent log file."""
        self.history_table.setRowCount(0)
        
        # 1. Dynamically scan the directory for the newest log file
        current_log_file = None
        if os.path.exists(LOG_DIR):
            try:
                # Find all files that look like agent logs
                valid_logs = [os.path.join(LOG_DIR, f) for f in os.listdir(LOG_DIR) if "agent" in f and "log" in f]
                
                if valid_logs:
                    # Smart fetch: Grab the file with the most recent modification timestamp!
                    current_log_file = max(valid_logs, key=os.path.getmtime)
            except Exception as e:
                print(f"Error finding dynamic log file: {e}")

        # If no files exist yet, just exit cleanly
        if not current_log_file or not os.path.exists(current_log_file):
            return
            
        # 2. Read the dynamically found file
        try:
            with open(current_log_file, 'r') as f:
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
            
            # proc_details = "N"
            # # proc_details = f"{event.get('process_name', 'N/A')} (PID: {event.get('pid', 'N/A')})"
            # if 'pid' in event: proc_details += f"\PID: {event.get('pid')}"
            # elif 'process_name' in event: proc_details += f"\nPath: {event.get('process_name')}"
            # elif 'path' in event: proc_details += f"\nPath: {event.get('path')}"
            # else : proc_details = "N/A"
            proc_details = " | ".join(
            filter(
                None,
                [
            f"PID: {event.get('pid')}" if event.get('pid') else "",
            f"Path: {event.get('process_name', event.get('path'))}"
            if event.get('process_name') or event.get('path')
            else "",
               ],
             )
            ) or "N/A"
            if e_type == "DOWNLOAD_DETECTED" : print(proc_details)
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
                
                # --- NEW: Inject the raw JSON data securely into the first column ---
                if col == 0:
                    item.setData(Qt.ItemDataRole.UserRole, text)

                table.setItem(row, col, item)

            # table.scrollToBottom()

            if table == self.live_table:
                self.apply_filter()
        except json.JSONDecodeError:
            pass

    def show_row_details(self, item):
        """Extracts the hidden JSON from the clicked row and shows the correct terminal."""
        table = item.tableWidget()
        row = item.row()
        first_col_item = table.item(row, 0)

        raw_json_str = first_col_item.data(Qt.ItemDataRole.UserRole)

        if raw_json_str:
            try:
                parsed_json = json.loads(raw_json_str)
                formatted_text = json.dumps(parsed_json, indent=4)
            except json.JSONDecodeError:
                formatted_text = raw_json_str

            # Route to the correct tab's terminal UI
            if table == getattr(self, 'live_table', None):
                # self.live_terminal_text.setText(formatted_text)
                #changed live_terminal_text to terminal_text to fix the issue of not showing the details in the live tab and crashing the app
                self.terminal_text.setText(formatted_text)
                
                self.live_terminal_frame.show()
                
            elif table == getattr(self, 'history_table', None):
                self.history_terminal_text.setText(formatted_text)
                self.history_terminal_frame.show()
                
            elif table == getattr(self, 'softwares_table', None):
                self.software_terminal_text.setText(formatted_text)
                self.software_terminal_frame.show()
                
    # def apply_filter(self):
    #     filter_text = self.filter_dropdown.currentText()
    #     for row in range(self.live_table.rowCount()):
    #         item = self.live_table.item(row, 1)
    #         if item:
    #             if filter_text == "High Severity Only" and item.text() != "High":
    #                 self.live_table.setRowHidden(row, True)
    #             else:
    #                 self.live_table.setRowHidden(row, False)

    def apply_filter(self):
        filter_text = self.filter_dropdown.currentText()
        # print(f"[DEBUG] Applying filter: {filter_text}") # Uncomment this to debug if needed
        
        for row in range(self.live_table.rowCount()):
            item = self.live_table.item(row, 1) # Column 1 is SEVERITY
            
            if item:
                # .strip().lower() removes trailing spaces and makes it case-insensitive to prevent mismatch errors
                severity_text = item.text().strip().lower() 
                hide_row = False
                
                if filter_text == "All Events":
                    hide_row = False
                elif filter_text == "High Severity Only" and severity_text != "high":
                    hide_row = True
                elif filter_text == "Medium Severity Only" and severity_text != "medium":
                    hide_row = True
                elif filter_text == "Low Severity Only" and severity_text != "low":
                    hide_row = True

                self.live_table.setRowHidden(row, hide_row)

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
        
        # 2. Safely get the icon path for PyInstaller using the new function
        icon_path = get_resource_path(os.path.join("assets", "guard.ico"))
        
        if os.path.exists(icon_path):
            guard_icon = QIcon(icon_path)
            self.tray.setIcon(guard_icon)
            self.app.setWindowIcon(guard_icon) # Sets the Taskbar and Window Icon
        else:
            self.tray.setIcon(app.style().standardIcon(app.style().StandardPixmap.SP_ComputerIcon))
        
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

    import json

    def route_message(self, text):
        """
        Acts as the main traffic cop for all incoming named pipe data.
        Parses the JSON and routes it to the correct UI processing function.
        """
        try:
            # 1. Parse the raw text string into a Python dictionary
            event = json.loads(text)
            event_type = event.get("type", "")

            # print(event)
            # 2. Check the type and route accordingly
            if event_type == "SOFTWARE_LIST":
                # Direct it to your new software tab handler
                self.main_window.load_softwares(text)
                
            else:
                # Send everything else (INSTALLER_DETECTED, NETWORK_CONNECTION, etc.) 
                # to the original live event processor
                self.main_window.process_live_event(text)

        except json.JSONDecodeError:
            print(f"Received malformed text over the pipe that wasn't valid JSON: {text}")

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