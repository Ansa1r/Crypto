from PyQt6.QtWidgets import QTreeWidget, QTreeWidgetItem, QHeaderView
from PyQt6.QtCore import Qt

class SecureTable(QTreeWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setHeaderLabels(["Title", "Username", "URL", "Notes", "Last Updated"])
        self.header().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.setColumnHidden(3, True)
        self.setSortingEnabled(True)
        self.sortByColumn(0, Qt.SortOrder.AscendingOrder)