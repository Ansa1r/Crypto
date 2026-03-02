from PyQt6.QtWidgets import QDialog, QVBoxLayout, QTableWidget, QTableWidgetItem, QPushButton

class AuditLogViewer(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Audit Log Viewer (Stub for Sprint 5)")
        self.setMinimumSize(600, 400)
        layout = QVBoxLayout(self)
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Timestamp", "Action", "Entry ID", "Details"])
        layout.addWidget(self.table)
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.close)
        layout.addWidget(close_btn)
        self._fill_stub_data()

    def _fill_stub_data(self):
        stub_logs = [
            ("2026-03-02 10:00", "Entry Added", "1", "Added Google account"),
            ("2026-03-02 11:15", "Entry Updated", "2", "Updated password"),
        ]
        self.table.setRowCount(len(stub_logs))
        for row, log in enumerate(stub_logs):
            for col, item in enumerate(log):
                self.table.setItem(row, col, QTableWidgetItem(item))