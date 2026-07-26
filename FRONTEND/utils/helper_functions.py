import json, sys, os
from PyQt6.QtCore import Qt

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
