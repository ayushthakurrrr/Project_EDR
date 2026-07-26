from PyQt6.QtWidgets import QFrame, QVBoxLayout, QHBoxLayout, QPushButton, QTextEdit
from PyQt6.QtCore import Qt

class TerminalPane(QFrame):
    def __init__(self):
        super().__init__()
        self.setup_ui()

    def setup_ui(self):
        # 1. Style the Frame itself
        self.setStyleSheet("""
            QFrame {
                background-color: #0d1117; 
                border: 1px solid #30363d; 
                border-radius: 5px;
            }
        """)
        
        terminal_layout = QVBoxLayout(self)
        terminal_layout.setContentsMargins(5, 5, 5, 5)

        # 2. Top bar for the Close Button
        close_btn_layout = QHBoxLayout()
        close_btn_layout.addStretch()
        
        self.close_btn = QPushButton("×") 
        self.close_btn.setFixedSize(24, 24)
        self.close_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.close_btn.setStyleSheet("""
            QPushButton { 
                background-color: #21262d; 
                color: #c9d1d9;            
                border: 1px solid #30363d; 
                border-radius: 12px;       
                font-family: Arial, sans-serif;
                font-size: 14px;           
                font-weight: 900;          
                padding: 0px;              
                margin: 0px;      
            } 
            QPushButton:hover { 
                background-color: #da3633; 
                color: #ffffff;            
                border: 1px solid #da3633;
            }
            QPushButton:pressed {
                background-color: #b32d2a; 
            }
        """)
        
        # Connect the button directly to the frame's built-in hide() method
        self.close_btn.clicked.connect(self.hide)
        close_btn_layout.addWidget(self.close_btn)

        # 3. The Text Area
        self.terminal_text = QTextEdit()
        self.terminal_text.setReadOnly(True)
        self.terminal_text.setStyleSheet("""
            color: #79c0ff; 
            font-family: Consolas, monospace; 
            font-size: 13px; 
            border: none;
        """)

        # 4. Assemble
        terminal_layout.addLayout(close_btn_layout)
        terminal_layout.addWidget(self.terminal_text)
        
        # Hide it by default until a row is clicked
        self.hide()

    def set_content(self, text):
        """Helper to update text and show the pane in one step."""
        self.terminal_text.setText(text)
        self.show()

    def clear_content(self):
        """Helper to clear the text."""
        self.terminal_text.clear()