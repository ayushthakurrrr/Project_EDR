# def apply_modern_theme(self):
#     """Applies a highly polished, VS Code / GitHub style dark mode."""
#     self.setStyleSheet("""
#         QMainWindow, QWidget {
#             background-color: #0d1117;
#             color: #c9d1d9;
#             font-family: 'Segoe UI', system-ui, sans-serif;
#             font-size: 13px;
#         }
#         QTabWidget::pane {
#             border: 1px solid #30363d;
#             border-radius: 8px;
#             background-color: #161b22;
#             margin-top: -1px;
#         }
#         QTabBar::tab {
#             background: #0d1117;
#             color: #8b949e;
#             padding: 10px 24px;
#             border: 1px solid transparent;
#             border-top-left-radius: 8px;
#             border-top-right-radius: 8px;
#             font-weight: bold;
#         }
#         QTabBar::tab:selected {
#             background: #161b22;
#             color: #58a6ff;
#             border: 1px solid #30363d;
#             border-bottom-color: #161b22;
#         }
#         QTabBar::tab:hover:!selected {
#             background: #21262d;
#             color: #c9d1d9;
#         }
#         QTableWidget {
#             background-color: #0d1117;
#             color: #c9d1d9;
#             border: none;
#             gridline-color: #30363d;
#             selection-background-color: #1f6feb;
#             border-radius: 8px;
#         }
#         QHeaderView::section {
#             background-color: #161b22;
#             color: #8b949e;
#             padding: 10px;
#             border: none;
#             border-right: 1px solid #30363d;
#             border-bottom: 1px solid #30363d;
#             font-weight: bold;
#             text-transform: uppercase;
#         }
#         QPushButton {
#             background-color: #238636;
#             color: #ffffff;
#             border: 1px solid rgba(240, 246, 252, 0.1);
#             padding: 8px 20px;
#             border-radius: 6px;
#             font-weight: bold;
#         }
#         QPushButton:hover {
#             background-color: #2ea043;
#         }
#         QPushButton:pressed {
#             background-color: #1a6428;
#         }
#         QComboBox {
#             background-color: #161b22;
#             color: #c9d1d9;
#             border: 1px solid #30363d;
#             border-radius: 6px;
#             padding: 6px 12px;
#         }
#         QComboBox::drop-down {
#             border: none;
#         }
#         QComboBox QAbstractItemView {
#             background-color: #161b22;
#             border: 1px solid #30363d;
#             selection-background-color: #1f6feb;
#         }
#     """)

def apply_modern_theme(self):
    """Returns only the structural/layout CSS to be combined with pyqtdarktheme."""
    return """
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
    """