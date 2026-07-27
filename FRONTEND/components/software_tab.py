from PyQt6.QtWidgets import QWidget, QVBoxLayout,QHBoxLayout, QPushButton, QTableWidget, QHeaderView, QSplitter, QTableWidgetItem, QAbstractItemView
from PyQt6.QtCore import Qt
import json

from workers.pipe_listener import send_backend_command
from utils.helper_functions import display_row_details
from components.terminal_pane import TerminalPane

class SoftwareTab(QWidget):
    def __init__(self):
        super().__init__()
        self.setup_softwares_tab()

    def setup_softwares_tab(self):
        # 1. Create the main layout for this tab
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        btn_layout = QHBoxLayout()
        self.refresh_softwares_btn = QPushButton("🔄 Refresh Installed Software")
        self.refresh_softwares_btn.setEnabled(True) 

        # 2. Connect it to the command sender
        self.refresh_softwares_btn.clicked.connect(lambda: send_backend_command("REFRESH_SOFTWARE"))

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
        
        self.softwares_table.itemClicked.connect(
            lambda item: display_row_details(item, self.terminal_pane)
        )

        # --- Build the Software Terminal Pane ---
        self.terminal_pane = TerminalPane()

        # --- Splitter Setup ---
        self.software_splitter = QSplitter(Qt.Orientation.Vertical)
        self.software_splitter.addWidget(self.softwares_table)
        self.software_splitter.addWidget(self.terminal_pane)
        self.software_splitter.setSizes([750, 250])
        
        layout.addWidget(self.software_splitter)
        self.terminal_pane.hide()

    def load_softwares(self, software_list):
        """Populates the Softwares table using the list from the telemetry thread."""
        try:
            # 1. Clear the table before loading the new list
            self.softwares_table.setRowCount(0)
            self.softwares_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)

            # 2. Loop through the Python list passed directly from the signal
            for software in software_list:
                row = self.softwares_table.rowCount()
                self.softwares_table.insertRow(row)

                display_name_item = QTableWidgetItem(software.get("display_name") or "N/A")
                display_name_item.setData(Qt.ItemDataRole.UserRole, json.dumps(software))
                
                self.softwares_table.setItem(row, 0, display_name_item)
                
                # Use 'or' to catch empty strings ("") or None values
                version = software.get("version") or "N/A"
                publisher = software.get("publisher") or "N/A"
                install_location = software.get("install_location") or "N/A"

                self.softwares_table.setItem(row, 1, QTableWidgetItem(version))
                self.softwares_table.setItem(row, 2, QTableWidgetItem(publisher))
                self.softwares_table.setItem(row, 3, QTableWidgetItem(install_location))
                
                # --- INSTALL DATE FORMATTING LOGIC ---
                raw_date = software.get("install_date") or ""
                display_date = "N/A"
                
                if raw_date:
                    if len(raw_date) == 8 and raw_date.isdigit():
                        display_date = f"{raw_date[:4]}-{raw_date[4:6]}-{raw_date[6:]}"
                    else:
                        display_date = raw_date 

                self.softwares_table.setItem(row, 4, QTableWidgetItem(display_date))
                
        except Exception as e:
            print(f"Failed to populate software table: {e}")