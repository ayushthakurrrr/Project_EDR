import json, sys, os
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor

def display_row_details(item, terminal_pane):
    """
    Extracts the hidden JSON from the clicked row of any table 
    and displays it in the provided terminal pane.
    """
    row = item.row()
    table = item.tableWidget()  # Dynamically grabs the table this item belongs to!
    
    if not table:
        return

    first_col_item = table.item(row, 0)
    if not first_col_item:
        return

    raw_json_str = first_col_item.data(Qt.ItemDataRole.UserRole)

    if raw_json_str:
        try:
            parsed_json = json.loads(raw_json_str)
            formatted_text = json.dumps(parsed_json, indent=4)
        except json.JSONDecodeError:
            formatted_text = raw_json_str

        # Pass the formatted text to the modular terminal pane
        terminal_pane.set_content(formatted_text)


def get_resource_path(relative_path):
    """ Safely get absolute path to resource, works for dev and for PyInstaller """
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)


def get_row_colors(self, engine_severity, e_type):
        """Returns a unified (background_color, text_color, severity) that works in any theme."""
        severity = engine_severity
        
        if engine_severity == "CRITICAL":
            bg_color = QColor("#4a2323")  # Muted deep red
            text_color = QColor("#ff9999") # Soft bright red
            
        elif engine_severity == "HIGH":
            bg_color = QColor("#4a3320")  # Muted deep orange
            text_color = QColor("#ffb870") # Soft bright orange
            
        elif engine_severity == "MEDIUM":
            bg_color = QColor("#423d20")  # Muted deep yellow/olive
            text_color = QColor("#e5c07b") # Soft golden yellow

        # Fallback to default Event Type coloring
        elif e_type in ["INSTALLER_DETECTED", "PERSISTENCE_DETECTED", "DOWNLOAD_DETECTED"]:
            bg_color = QColor("#4a2323")
            text_color = QColor("#ff9999")
            severity = "High"
            
        elif e_type == "NETWORK_CONNECTION":
            bg_color = QColor("#22334a")  # Muted deep blue
            text_color = QColor("#79c0ff") # Soft bright blue
            severity = "Medium"
            
        elif e_type in ["USER_SESSION_STARTED", "USER_SESSION_ENDED", "SYSTEM_BOOT_INFO"]:
            bg_color = QColor("#30224a")  # Muted deep purple
            text_color = QColor("#b392f0") # Soft bright purple
            severity = "Info"
            
        else:
            severity = "Low"
            # bg_color = QColor("#2b2d30")  # Universal Slate Gray
            # text_color = QColor("#a9b7c6") # Soft Silver
            bg_color = None
            text_color = None
            
            if e_type == "UAC_DETECTED": 
                bg_color = QColor("#423d20")
                text_color = QColor("#e5c07b")
                
        return bg_color, text_color, severity