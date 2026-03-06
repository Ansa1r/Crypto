from PyQt6.QtWidgets import QDialog, QVBoxLayout, QTableWidget, QTableWidgetItem, QPushButton, QHeaderView
from PyQt6.QtCore import Qt
from src.database.db import get_audit_logs


class AuditLogViewer(QDialog):
    def __init__(self, parent=None, db_path=None):
        super().__init__(parent)
        self.db_path = db_path
        self.setWindowTitle("Audit Log Viewer")
        self.setMinimumSize(700, 500)

        layout = QVBoxLayout(self)

        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Timestamp", "Action", "Entry ID", "Details"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)

        layout.addWidget(self.table)

        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self.load_logs)
        layout.addWidget(self.refresh_button)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.close)
        layout.addWidget(close_btn)

        self.load_logs()

    def load_logs(self):
        if not self.db_path:
            return

        logs = get_audit_logs(100, self.db_path)
        self.table.setRowCount(len(logs))

        for row, log in enumerate(logs):
            self.table.setItem(row, 0, QTableWidgetItem(log.get('timestamp', '')))
            self.table.setItem(row, 1, QTableWidgetItem(log.get('action', '')))
            self.table.setItem(row, 2, QTableWidgetItem(str(log.get('entry_id', '')) if log.get('entry_id') else ''))
            self.table.setItem(row, 3, QTableWidgetItem(log.get('details', '')))