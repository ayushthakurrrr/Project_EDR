import json, os
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QComboBox, 
                             QLabel, QPushButton, QSplitter, QTableWidgetItem, QHeaderView, QTableWidget)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QFont

from components.terminal_pane import TerminalPane
from utils.helper_functions import display_row_details

PROGRAM_DATA = os.environ.get('PROGRAMDATA', r'C:\ProgramData')
LOG_DIR = os.path.join(PROGRAM_DATA, "EdrAgent")

class HistoryTab(QWidget):
    def __init__(self):
        super().__init__()
        self.setup_ui()

    def setup_ui(self):
        # Main layout for the history tab
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # --- 1. Top Controls (Refresh & Filters) ---
        btn_layout = QHBoxLayout()

        
        
        # Refresh Button
        self.refresh_btn = QPushButton("🔄 Refresh Log History")
        self.refresh_btn.clicked.connect(self.populate_file_dropdown) # Now updates the file list
        self.refresh_btn.clicked.connect(self.load_history)
        btn_layout.addWidget(self.refresh_btn)
        btn_layout.addStretch()
        # NEW: Log File Selector Dropdown
        self.file_selector = QComboBox()
        self.file_selector.setMinimumWidth(200)
        self.file_selector.currentTextChanged.connect(self.load_history) # Auto-load on change
        
        btn_layout.addWidget(QLabel("Log File:"))
        btn_layout.addWidget(self.file_selector)

        # Type Filter
        self.type_filter = QComboBox()
        self.type_filter.addItem("All Event Types")
        btn_layout.addWidget(QLabel("Type:"))
        btn_layout.addWidget(self.type_filter)

        # Severity Filter
        self.severity_filter = QComboBox()
        self.severity_filter.addItem("All Severities")
        btn_layout.addWidget(QLabel("Severity:"))
        btn_layout.addWidget(self.severity_filter)

        # Date Filter
        self.date_filter = QComboBox()
        self.date_filter.addItem("All Dates")
        btn_layout.addWidget(QLabel("Date:"))
        btn_layout.addWidget(self.date_filter)

        # Apply Filter Button
        self.filter_btn = QPushButton("Apply Filter")
        self.filter_btn.clicked.connect(self.apply_history_filter)
        btn_layout.addWidget(self.filter_btn)

        layout.addLayout(btn_layout)

        self.history_events = []
        
        # --- 2. History Table ---
        self.history_table = self.create_event_table()
        self.history_table.itemClicked.connect(
            lambda item: display_row_details(item, self.terminal_pane)
        )

        # --- 3. Modular Terminal Pane ---
        self.terminal_pane = TerminalPane()

        # --- 4. Splitter Setup ---
        self.history_splitter = QSplitter(Qt.Orientation.Vertical)
        self.history_splitter.addWidget(self.history_table)
        self.history_splitter.addWidget(self.terminal_pane)
        self.history_splitter.setSizes([750, 250])
        
        layout.addWidget(self.history_splitter)
        
        self.terminal_pane.hide()

        # Initial population of the dropdown when tab is created
        self.populate_file_dropdown()

    def populate_file_dropdown(self):
        """Scans the LOG_DIR and populates the dropdown with available log files."""
        # Temporarily disconnect the signal so clearing/adding doesn't trigger load_history
        self.file_selector.blockSignals(True)
        self.file_selector.clear()

        if os.path.exists(LOG_DIR):
            try:
                # Find all log files
                valid_logs = [f for f in os.listdir(LOG_DIR) if "agent" in f and "log" in f]
                
                if valid_logs:
                    # Sort them descending (newest file at the top of the list)
                    valid_logs.sort(reverse=True)
                    self.file_selector.addItems(valid_logs)
            except Exception as e:
                print(f"Error finding log files: {e}")
                
        if self.file_selector.count() == 0:
            self.file_selector.addItem("No log files found")
            
        # Reconnect the signal and load whatever is selected
        self.file_selector.blockSignals(False)
        self.load_history()

    # def load_history(self):
    #     """Dynamically finds and loads the most recent log file."""
    #     self.history_events.clear()
    #     self.history_table.setRowCount(0)
        
    #     # 1. Dynamically scan the directory for the newest log file
    #     current_log_file = None
        
    #     if os.path.exists(LOG_DIR):
    #         try:
    #             # Find all files that look like agent logs
    #             valid_logs = [os.path.join(LOG_DIR, f) for f in os.listdir(LOG_DIR) if "agent" in f and "log" in f]
                
    #             if valid_logs:
    #                 # Smart fetch: Grab the file with the most recent modification timestamp!
    #                 current_log_file = max(valid_logs, key=os.path.getmtime)
    #         except Exception as e:
    #             print(f"Error finding dynamic log file: {e}")

    #     # If no files exist yet, just exit cleanly
    #     if not current_log_file or not os.path.exists(current_log_file):
    #         return
            
    #     # 2. Read the dynamically found file
    #     try:
    #         with open(current_log_file, 'r') as f:
    #             for line in f:
    #                 if " | " in line:
    #                     json_str = line.split(" | ", 1)[1]
    #                     try:
    #                         event = json.loads(json_str)
    #                         if isinstance(event, dict):
    #                            self.history_events.append(event)
    #                     except json.JSONDecodeError:
    #                         pass
    #                 elif line.startswith("{"):
    #                     try:
    #                         event = json.loads(line)
    #                         if isinstance(event, dict):
    #                            self.history_events.append(event)
    #                     except json.JSONDecodeError:
    #                         pass
    #     except Exception as e:
    #         print(f"Error loading history: {e}")

    #     self.populate_history_filters()
    #     self.apply_history_filter() 
    def load_history(self):
        """Loads events from the specific log file chosen in the dropdown."""
        self.history_events.clear()
        self.history_table.setRowCount(0)
        
        selected_file = self.file_selector.currentText()
        if not selected_file or selected_file == "No log files found":
            return
            
        current_log_file = os.path.join(LOG_DIR, selected_file)
        
        if not os.path.exists(current_log_file):
            return
            
        # Read the explicitly selected file
        try:
            with open(current_log_file, 'r') as f:
                for line in f:
                    if " | " in line:
                        json_str = line.split(" | ", 1)[1]
                        try:
                            event = json.loads(json_str)
                            if isinstance(event, dict):
                               self.history_events.append(event)
                        except json.JSONDecodeError:
                            pass
                    elif line.startswith("{"):
                        try:
                            event = json.loads(line)
                            if isinstance(event, dict):
                               self.history_events.append(event)
                        except json.JSONDecodeError:
                            pass
        except Exception as e:
            print(f"Error loading history file {current_log_file}: {e}")

        # Populate internal filters (Type/Severity/Date based on the newly loaded file)
        self.populate_history_filters()
        self.apply_history_filter()  

    def populate_history_filters(self):
        current_type = self.type_filter.currentText()
        current_date = self.date_filter.currentText()

        types = sorted({
            e.get("type", "Unknown")
            for e in self.history_events
        })

        dates = sorted({
            e.get("timestamp", "")[:10]
            for e in self.history_events
        })

        severities = sorted({
            self.get_event_severity(e)
            for e in self.history_events
        })

        self.type_filter.clear()
        self.type_filter.addItem("All Event Types")
        self.type_filter.addItems(types)

        self.date_filter.clear()
        self.date_filter.addItem("All Dates")
        self.date_filter.addItems(dates)

        self.severity_filter.clear()
        self.severity_filter.addItem("All Severities")
        self.severity_filter.addItems(severities)

    def get_event_severity(self, event):
        """Determines severity based on event type."""
        e_type = event.get("type", "")

        if e_type in ["INSTALLER_DETECTED", "PERSISTENCE_DETECTED", "DOWNLOAD_DETECTED"]:
            return "High"
        elif e_type == "NETWORK_CONNECTION":
            return "Medium"
        elif e_type in ["USER_SESSION_STARTED", "USER_SESSION_ENDED", "SYSTEM_BOOT_INFO"]:
            return "Info"
        elif e_type == "UAC_DETECTED":
            return "Medium"
        else:
            return "Low"
        
    def apply_history_filter(self):
        """Applies dropdown filters to the history table."""
        self.history_table.setRowCount(0)

        # Using the simplified combo box names from setup_ui
        selected_type = self.type_filter.currentText()
        selected_date = self.date_filter.currentText()
        selected_severity = self.severity_filter.currentText()

        for event in self.history_events:
            event_type = event.get("type", "")
            event_date = event.get("timestamp", "")[:10]
            event_severity = self.get_event_severity(event)

            if selected_type != "All Event Types" and event_type != selected_type:
                continue
            if selected_date != "All Dates" and event_date != selected_date:
                continue
            if selected_severity != "All Severities" and event_severity != selected_severity:
                continue    

            # No need to pass the table argument anymore, we know it's self.history_table
            self.add_row_to_table(json.dumps(event)) 

    def add_row_to_table(self, text):
        """Parses JSON text and adds a colored row to the History table."""
        try:
            event = json.loads(text)

            if not isinstance(event, dict):
                print("Bad event type:", type(event))
                print("Raw text:", text)
                return

            row = self.history_table.rowCount()
            self.history_table.insertRow(row)

            # Modern Enterprise Colors (Subtle backgrounds, bright text)
            e_type = event.get("type", "")
            
            # 1. Grab the severity generated by threat_detection.py (default to None if missing)
            engine_severity = event.get("severity", "").upper()

            if engine_severity == "CRITICAL":
                severity = "CRITICAL"
                bg_color = QColor("#5a0000")  # Intense Dark Red Background
                text_color = QColor("#ff6666") # Bright Alert Red Text
            elif engine_severity == "HIGH":
                severity = "HIGH"
                bg_color = QColor("#4d1f00")  # Dark Orange/Brown Background
                text_color = QColor("#ff9933") # Bright Orange Text
            elif engine_severity == "MEDIUM":
                severity = "MEDIUM"
                bg_color = QColor("#3d3301")  # Dark Yellow Background
                text_color = QColor("#e3b341") # Bright Yellow Text

            # 2. Fallback to default Event Type coloring if Threat Engine didn't flag it
            elif e_type in ["INSTALLER_DETECTED", "PERSISTENCE_DETECTED", "DOWNLOAD_DETECTED"]:
                severity = "High"
                bg_color = QColor("#490202")  # Deep red background
                text_color = QColor("#ff7b72") # Bright red text
            elif e_type == "NETWORK_CONNECTION":
                severity = "Medium"
                bg_color = QColor("#0a3069")  # Deep blue background
                text_color = QColor("#79c0ff") # Bright blue text
            elif e_type in ["USER_SESSION_STARTED", "USER_SESSION_ENDED", "SYSTEM_BOOT_INFO"]:
                severity = "Info"
                bg_color = QColor("#1e0a3c")  # Deep purple background
                text_color = QColor("#a371f7") # Bright purple text
            else:
                severity = "Low"
                bg_color = QColor("#0d1117")  # Standard dark
                text_color = QColor("#c9d1d9")
                if e_type == "UAC_DETECTED": 
                    bg_color = QColor("#3d3301") # Deep yellow
                    text_color = QColor("#e3b341")
            
            # Process details parsing
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

            status = event.get("status","")

            if e_type in ["INCIDENT_RESPONSE","PROCESS_STATUS_UPDATE"]:
                status = event.get("status","UNKNOWN")

            items = [
                QTableWidgetItem(event.get("timestamp", "")),
                QTableWidgetItem(severity),
                QTableWidgetItem(e_type),
                QTableWidgetItem(proc_details),
                QTableWidgetItem(status),
                QTableWidgetItem(event.get("message", ""))
            ]

            for col, item in enumerate(items):
                item.setBackground(bg_color)
                item.setForeground(text_color)
                if col in [1, 2]:
                    font = QFont()
                    font.setBold(True)
                    item.setFont(font)
                
                # Inject the raw JSON data securely into the first column
                if col == 0:
                    item.setData(Qt.ItemDataRole.UserRole, text)

                self.history_table.setItem(row, col, item)

        except json.JSONDecodeError:
            pass

    def create_event_table(self):
        """Initializes and formats the history data table."""
        table = QTableWidget(0, 6)
        table.setHorizontalHeaderLabels([
            "TIMESTAMP", 
            "SEVERITY", 
            "EVENT TYPE", 
            "PROCESS / PATH", 
            "STATUS",
            "DETAILS"
        ])
        
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
        
        # --- GENERAL PROPERTIES ---
        table.setWordWrap(True)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setAlternatingRowColors(True)
        table.setShowGrid(False)

        table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        
        return table