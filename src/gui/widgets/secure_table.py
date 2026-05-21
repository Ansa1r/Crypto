from PyQt6.QtWidgets import QTreeWidget, QTreeWidgetItem, QHeaderView, QMenu, QAbstractItemView
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QAction


class SecureTable(QTreeWidget):
    itemCopyRequested = pyqtSignal(object)
    itemEditRequested = pyqtSignal(object)
    itemDeleteRequested = pyqtSignal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setHeaderLabels(["Title", "Username", "URL", "Last Modified"])
        self.header().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.header().setStretchLastSection(True)
        self.setSortingEnabled(True)
        self.sortByColumn(0, Qt.SortOrder.AscendingOrder)
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_context_menu)
        self._password_visible = False

        self.setColumnWidth(0, 200)
        self.setColumnWidth(1, 150)
        self.setColumnWidth(2, 200)
        self.setColumnWidth(3, 120)

    def mask_username(self, username: str) -> str:
        if not username:
            return ""
        if len(username) <= 4:
            return "••••"
        return username[:4] + "••••"

    def add_entry(self, entry: dict) -> QTreeWidgetItem:
        username_display = self.mask_username(entry.get('username', ''))
        if not self._password_visible:
            username_display = self.mask_username(entry.get('username', ''))
        else:
            username_display = entry.get('username', '')

        last_modified = entry.get('updated_at', entry.get('created_at', ''))
        if last_modified:
            last_modified = last_modified[:10] if len(last_modified) > 10 else last_modified

        item = QTreeWidgetItem([
            entry.get('title', ''),
            username_display,
            self.extract_domain(entry.get('url', '')),
            last_modified
        ])
        item.setData(0, Qt.ItemDataRole.UserRole, entry.get('id', ''))
        item.setData(1, Qt.ItemDataRole.UserRole, entry.get('username', ''))
        item.setData(2, Qt.ItemDataRole.UserRole, entry.get('url', ''))
        item.setData(3, Qt.ItemDataRole.UserRole, entry.get('password', ''))
        item.setData(4, Qt.ItemDataRole.UserRole, entry.get('notes', ''))
        item.setData(5, Qt.ItemDataRole.UserRole, entry.get('tags', ''))

        self.addTopLevelItem(item)
        return item

    def extract_domain(self, url: str) -> str:
        if not url:
            return ""
        url_lower = url.lower()
        if url_lower.startswith('https://'):
            url_lower = url_lower[8:]
        elif url_lower.startswith('http://'):
            url_lower = url_lower[7:]
        if url_lower.startswith('www.'):
            url_lower = url_lower[4:]
        domain = url_lower.split('/')[0]
        return domain

    def update_entry_username_display(self, item: QTreeWidgetItem):
        if not item:
            return
        username = item.data(1, Qt.ItemDataRole.UserRole)
        if not self._password_visible:
            item.setText(1, self.mask_username(username))
        else:
            item.setText(1, username)

    def refresh_all_usernames(self):
        for i in range(self.topLevelItemCount()):
            item = self.topLevelItem(i)
            self.update_entry_username_display(item)

    def toggle_password_visibility(self, visible: bool):
        self._password_visible = visible
        self.refresh_all_usernames()

    def is_password_visible(self) -> bool:
        return self._password_visible

    def load_entries(self, entries: list):
        self.clear()
        for entry in entries:
            self.add_entry(entry)

    def get_selected_entries(self) -> list:
        selected_items = self.selectedItems()
        entries = []
        for item in selected_items:
            entry = {
                'id': item.data(0, Qt.ItemDataRole.UserRole),
                'title': item.text(0),
                'username': item.data(1, Qt.ItemDataRole.UserRole),
                'password': item.data(3, Qt.ItemDataRole.UserRole),
                'url': item.data(2, Qt.ItemDataRole.UserRole),
                'notes': item.data(4, Qt.ItemDataRole.UserRole),
                'tags': item.data(5, Qt.ItemDataRole.UserRole)
            }
            entries.append(entry)
        return entries

    def get_selected_entry_ids(self) -> list:
        return [item.data(0, Qt.ItemDataRole.UserRole) for item in self.selectedItems()]

    def show_context_menu(self, position):
        item = self.itemAt(position)
        if not item:
            return

        menu = QMenu()

        copy_action = QAction("Copy Username", self)
        copy_action.triggered.connect(lambda: self.itemCopyRequested.emit(item))
        menu.addAction(copy_action)

        copy_password_action = QAction("Copy Password", self)
        copy_password_action.triggered.connect(lambda: self._on_copy_password(item))
        menu.addAction(copy_password_action)

        menu.addSeparator()

        edit_action = QAction("Edit", self)
        edit_action.triggered.connect(lambda: self.itemEditRequested.emit(item))
        menu.addAction(edit_action)

        delete_action = QAction("Delete", self)
        delete_action.triggered.connect(lambda: self.itemDeleteRequested.emit(item))
        menu.addAction(delete_action)

        menu.addSeparator()

        show_password_action = QAction("Show/Hide Password", self)
        show_password_action.triggered.connect(lambda: self.itemCopyRequested.emit(item))
        menu.addAction(show_password_action)

        menu.exec(self.viewport().mapToGlobal(position))

    def _on_copy_password(self, item):
        password = item.data(3, Qt.ItemDataRole.UserRole)
        if password:
            from PyQt6.QtWidgets import QApplication
            QApplication.clipboard().setText(password)

    def get_item_by_id(self, entry_id: str) -> QTreeWidgetItem:
        for i in range(self.topLevelItemCount()):
            item = self.topLevelItem(i)
            if item.data(0, Qt.ItemDataRole.UserRole) == entry_id:
                return item
        return None

    def remove_entry_by_id(self, entry_id: str) -> bool:
        item = self.get_item_by_id(entry_id)
        if item:
            index = self.indexOfTopLevelItem(item)
            self.takeTopLevelItem(index)
            return True
        return False

    def update_entry_in_table(self, entry: dict):
        item = self.get_item_by_id(entry.get('id', ''))
        if item:
            username_display = self.mask_username(entry.get('username', ''))
            if self._password_visible:
                username_display = entry.get('username', '')

            item.setText(0, entry.get('title', ''))
            item.setText(1, username_display)
            item.setText(2, self.extract_domain(entry.get('url', '')))

            last_modified = entry.get('updated_at', entry.get('created_at', ''))
            if last_modified:
                last_modified = last_modified[:10] if len(last_modified) > 10 else last_modified
            item.setText(3, last_modified)

            item.setData(0, Qt.ItemDataRole.UserRole, entry.get('id', ''))
            item.setData(1, Qt.ItemDataRole.UserRole, entry.get('username', ''))
            item.setData(2, Qt.ItemDataRole.UserRole, entry.get('url', ''))
            item.setData(3, Qt.ItemDataRole.UserRole, entry.get('password', ''))
            item.setData(4, Qt.ItemDataRole.UserRole, entry.get('notes', ''))
            item.setData(5, Qt.ItemDataRole.UserRole, entry.get('tags', ''))

    def clear_selection(self):
        self.clearSelection()

    def select_all(self):
        self.selectAll()

    def get_entry_count(self) -> int:
        return self.topLevelItemCount()

    def sort_by_column(self, column: int, order: Qt.SortOrder = None):
        if order is None:
            current_order = self.header().sortIndicatorOrder()
            new_order = Qt.SortOrder.AscendingOrder if current_order == Qt.SortOrder.DescendingOrder else Qt.SortOrder.DescendingOrder
        else:
            new_order = order
        self.sortItems(column, new_order)
        self.header().setSortIndicator(column, new_order)