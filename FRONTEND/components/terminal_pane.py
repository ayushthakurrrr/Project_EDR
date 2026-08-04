from PyQt6.QtWidgets import QFrame, QVBoxLayout, QHBoxLayout, QPushButton, QTextEdit
from PyQt6.QtCore import Qt

class TerminalPane(QFrame):
    def __init__(self):
        super().__init__()
        self.setObjectName("TerminalFrame") # <-- Assign an ID for CSS
        self.setup_ui()

    def setup_ui(self):
        terminal_layout = QVBoxLayout(self)
        terminal_layout.setContentsMargins(5, 5, 5, 5)

        # Top bar for the Close Button
        close_btn_layout = QHBoxLayout()
        close_btn_layout.addStretch()
        
        self.close_btn = QPushButton("×") 
        self.close_btn.setObjectName("TerminalCloseBtn") # <-- Assign an ID for CSS
        self.close_btn.setFixedSize(24, 24)
        self.close_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        
        self.close_btn.clicked.connect(self.hide)
        close_btn_layout.addWidget(self.close_btn)

        # The Text Area
        self.terminal_text = QTextEdit()
        self.terminal_text.setObjectName("TerminalText") # <-- Assign an ID for CSS
        self.terminal_text.setReadOnly(True)

        # Assemble
        terminal_layout.addLayout(close_btn_layout)
        terminal_layout.addWidget(self.terminal_text)
        
        # Hide it by default until a row is clicked
        self.hide()

    def set_content(self, text):
        self.terminal_text.setText(text)
        self.show()

    def clear_content(self):
        self.terminal_text.clear()