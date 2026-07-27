from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QComboBox, 
                             QLabel, QSplitter, QTableWidget, QHeaderView, QMenu, QTableWidgetItem)
from PyQt6.QtGui import QAction, QColor, QFont
from PyQt6.QtCore import Qt, pyqtSignal

import json

from components.terminal_pane import TerminalPane
from workers.pipe_listener import send_backend_command
from utils.helper_functions import display_row_details

class LiveStreamTab(QWidget):
    alert_received = pyqtSignal(int)
    def __init__(self):
        super().__init__()
        self.total_alerts = 0
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)

        # --- 1. Filters (Top Section) ---
        control_layout = QHBoxLayout()
        self.filter_dropdown = QComboBox()
        self.filter_dropdown.addItems(["All Events", "High Severity", "Medium Severity", "Low Severity"])
        self.filter_dropdown.currentTextChanged.connect(self.apply_filter)
        
        control_layout.addWidget(QLabel("FILTER EVENTS:"))
        control_layout.addWidget(self.filter_dropdown)
        control_layout.addStretch()
        
        layout.addLayout(control_layout)

        # --- 2. Table ---
        self.live_table = self.create_event_table() 
        self.live_table.itemClicked.connect(
            lambda item: display_row_details(item, self.terminal_pane)
        )
        self.live_table.customContextMenuRequested.connect(self.show_live_context_menu)

        # --- 3. Modular Terminal ---
        self.terminal_pane = TerminalPane()

        # --- 4. Splitter (Bottom Section) ---
        self.main_splitter = QSplitter(Qt.Orientation.Vertical)
        self.main_splitter.addWidget(self.live_table)
        self.main_splitter.addWidget(self.terminal_pane)
        self.main_splitter.setSizes([750, 250])
        
        # Add the splitter right below the filters
        layout.addWidget(self.main_splitter)
                
        self.terminal_pane.hide()

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
                elif filter_text == "High Severity" and severity_text != "high":
                    hide_row = True
                elif filter_text == "Medium Severity" and severity_text != "medium":
                    hide_row = True
                elif filter_text == "Low Severity" and severity_text != "low":
                    hide_row = True

                self.live_table.setRowHidden(row, hide_row)

    def create_event_table(self):
        table = QTableWidget(0, 6)
        table.setHorizontalHeaderLabels(["TIMESTAMP", "SEVERITY", "EVENT TYPE", "PROCESS / PATH", "STATUS","DETAILS"])
        
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

        table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        return table

    def show_live_context_menu(self, position):
        item = self.live_table.itemAt(position)
        if not item:
            return
        row = item.row()
        first_item = self.live_table.item(row, 0)

        raw_json = first_item.data(Qt.ItemDataRole.UserRole)

        if not raw_json:
            return

        try:
            event = json.loads(raw_json)
        except:
            return

        pid = event.get("pid")
        process_name = event.get("process_name", "Unknown")
        menu = QMenu(self)

        status_item = self.live_table.item(row, 4)  # STATUS column
        current_status = status_item.text().upper() if status_item else ""

        # Only show process actions if a PID exists
        if pid and process_name and current_status not in ("KILLED", "STOPPED"):

            kill_action = QAction(
                f"Kill Process ({process_name})",
                self
            )

            kill_action.triggered.connect(
                lambda: send_backend_command(
                    "KILL_PROCESS",
                    pid
                )
            )
            restart_action = QAction(
                f"Restart Process ({process_name})",self
            )

            restart_action.triggered.connect(
                lambda: send_backend_command( "RESTART_PROCESS",pid))

            stop_action = QAction( f"Stop Process ({process_name})",self)
            stop_action.triggered.connect(lambda: send_backend_command("STOP_PROCESS",pid)
        )

            menu.addAction(kill_action)
            menu.addAction(stop_action)
            menu.addAction(restart_action)
            menu.addSeparator()

        details_action = QAction("View Details",self)
        details_action.triggered.connect(
            lambda checked=False: display_row_details(self.live_table.currentItem(), self.terminal_pane) if self.live_table.currentItem() else None
        )

        menu.addAction(details_action)
        menu.exec(self.live_table.viewport().mapToGlobal(position))

    def add_row_to_table(self, text):
        """Parses JSON text and adds a colored row to the Live stream table."""
        try:
            event = json.loads(text)

            if not isinstance(event, dict):
                print("Bad event type:", type(event))
                print("Raw text:", text)
                return
            
            self.total_alerts += 1
            # Broadcast the new count to the MainWindow (which updates the label)
            self.alert_received.emit(self.total_alerts)

            # Insert new row
            row = self.live_table.rowCount()
            self.live_table.insertRow(row)

            # Extract type with fallback
            e_type = event.get("type") or "N/A"

            # Grab the severity generated by threat_detection.py (safely handle None)
            engine_severity = (event.get("severity") or "").upper()
            
            # Modern Enterprise Colors (Subtle backgrounds, bright text)
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

            # Fallback to default Event Type coloring if Threat Engine didn't flag it
            elif e_type in ["INSTALLER_DETECTED", "PERSISTENCE_DETECTED", "DOWNLOAD_DETECTED"]:
                severity = "High"
                bg_color = QColor("#490202")  # Deep red background
                text_color = QColor("#ff7b72") # Bright red text
            elif e_type == "NETWORK_CONNECTION":
                severity = "Medium"
                bg_color = QColor("#0a3069")  # Deep blue background
                text_color = QColor("#79c0ff") # Bright blue text
            # Highlight User Sessions & Boots
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
            
            # Process details parsing with safe fallbacks
            proc_details = " | ".join(
                filter(
                    None,
                    [
                        f"PID: {event.get('pid')}" if event.get('pid') else "",
                        f"Path: {event.get('process_name') or event.get('path')}"
                        if event.get('process_name') or event.get('path')
                        else "",
                    ],
                )
            ) or "N/A"

            # Apply robust fallback for Status
            status = event.get("status") or "N/A"
            if e_type in ["INCIDENT_RESPONSE", "PROCESS_STATUS_UPDATE"]:
                status = event.get("status") or "UNKNOWN"

            # Apply robust fallback for Timestamp and Message
            timestamp = event.get("timestamp") or "N/A"
            message = event.get("message") or "N/A"

            items = [
                QTableWidgetItem(timestamp),
                QTableWidgetItem(severity),
                QTableWidgetItem(e_type),
                QTableWidgetItem(proc_details),
                QTableWidgetItem(status),
                QTableWidgetItem(message)
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

                self.live_table.setItem(row, col, item)

            # self.live_table.scrollToBottom()

            # Apply any active UI filters immediately to the new row
            self.apply_filter()
            
        except json.JSONDecodeError:
            pass

    def update_incident_status(self, pid, status):
        """Updates the status column for a specific PID in the live table."""
        pid = str(pid)

        for row in range(self.live_table.rowCount()):
            process_item = self.live_table.item(row, 3)
            
            if not process_item:
                continue

            process_text = process_item.text()
            if f"PID: {pid}" in process_text:
                status_item = self.live_table.item(row, 4)

                if status_item:
                    status_item.setText(status)
                    if status.upper() == "RUNNING":
                        status_item.setForeground(QColor("#3fb950"))
                    elif status.upper() in ["STOPPED", "KILLED"]:
                        status_item.setForeground(QColor("#ff7b72"))
                    elif status.upper() == "SUCCESS":
                        status_item.setForeground(QColor("#3fb950"))
                    else:
                        status_item.setForeground(QColor("#d29922"))
                return