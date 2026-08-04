from PyQt6.QtWidgets import QApplication
def apply_modern_theme(theme_mode="auto"):
        import qdarktheme
        app = QApplication.instance()
        
        # 1. Load the base theme from qdarktheme
        base_theme_css = qdarktheme.load_stylesheet(theme_mode)
        
        # 2. Your custom structural CSS
        custom_base_css = """
        QMainWindow, QWidget {
            font-family: 'Segoe UI', system-ui, sans-serif;
            font-size: 13px;
        }
        QTabWidget::pane {
            border-width: 1px;
            border-radius: 8px;
            margin-top: -1px;
        }
        QTabBar::tab {
            border-width: 1px;
            padding: 10px 24px;
            border-top-left-radius: 8px;
            border-top-right-radius: 8px;
            font-weight: bold;
        }
        QTabBar::tab:selected {
            border-width: 1px;
        }
        QTableWidget {
            border: none;
            border-radius: 8px;
        }
        QHeaderView::section {
            padding: 10px;
            border: none;
            font-weight: bold;
            text-transform: uppercase;
        }
        QPushButton {
            border-width: 1px;
            padding: 8px 20px;
            border-radius: 6px;
            font-weight: bold;
        }
        QComboBox {
            border-radius: 6px;
            border-width: 1px;
            padding: 6px 12px;
        }
        QComboBox::drop-down {
            border: none;
        }
        QComboBox QAbstractItemView {
            border-width: 1px;
        }
        QFrame#TerminalFrame {
                border-radius: 5px;
                border: 1px solid;
        }
        QPushButton#TerminalCloseBtn {
            border-radius: 12px;       
            font-family: Arial, sans-serif;
            font-size: 14px;           
            font-weight: 900;          
            padding: 0px;              
            margin: 0px; 
            border: 1px solid;
        }
        QTextEdit#TerminalText {
            font-family: Consolas, monospace; 
            font-size: 13px; 
            border: none;
            background-color: transparent;
        }
    """

    # 3. Your custom state-based colors
        if theme_mode == "dark":
            custom_color_css = """
                QLabel#FooterBadge { background-color: #161b22; color: #8b949e; }
                QLabel#AlertBadge { background-color: #161b22; color: #ff7b72; }
                
                QLabel#FooterBadge[statusState="connected"] { color: #3fb950; }
                QLabel#FooterBadge[statusState="partial"] { color: #d29922; }
                QLabel#FooterBadge[statusState="disconnected"] { color: #ff7b72; }
                
                QPushButton:checked { background-color: #da3633; color: #ffffff; border: 1px solid #ff7b72; }
                QFrame#TerminalFrame { background-color: #0d1117; border-color: #30363d; }
                
                QPushButton#TerminalCloseBtn { background-color: #21262d; color: #c9d1d9; border-color: #30363d; }
                QPushButton#TerminalCloseBtn:hover { background-color: #da3633; color: #ffffff; border-color: #da3633; }
                QPushButton#TerminalCloseBtn:pressed { background-color: #b32d2a; }
                
                QTextEdit#TerminalText { color: #79c0ff; }
            """
        else:
            custom_color_css = """
                QLabel#FooterBadge { background-color: #f6f8fa; color: #57606a; }
                QLabel#AlertBadge { background-color: #ffebe9; color: #cf222e; }
                
                QLabel#FooterBadge[statusState="connected"] { color: #1a7f37; }
                QLabel#FooterBadge[statusState="partial"] { color: #9a6700; }
                QLabel#FooterBadge[statusState="disconnected"] { color: #cf222e; }
                
                QPushButton:checked { background-color: #cf222e; color: #ffffff; border: 1px solid #a40e26; }
                QFrame#TerminalFrame { background-color: #f6f8fa; border-color: #d0d7de; }
                
                QPushButton#TerminalCloseBtn { background-color: #ebf0f4; color: #57606a; border-color: #d0d7de; }
                QPushButton#TerminalCloseBtn:hover { background-color: #cf222e; color: #ffffff; border-color: #cf222e; }
                QPushButton#TerminalCloseBtn:pressed { background-color: #a40e26; }
                
                QTextEdit#TerminalText { color: #0550ae; }
            """
            
        # 4. Merge them together and apply to the whole app!
        # Your custom CSS overrides pyqtdarktheme because it comes last
        final_stylesheet = base_theme_css + custom_base_css + custom_color_css
        app.setStyleSheet(final_stylesheet)