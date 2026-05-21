from PyQt6.QtWidgets import QTreeWidget, QTreeWidgetItem, QHeaderView, QMenu, QAbstractItemView, QApplication, QStyle, \
    QStyleOptionButton, QPushButton, QWidget, QHBoxLayout
from PyQt6.QtCore import Qt, pyqtSignal, QRect, QPoint
from PyQt6.QtGui import QAction, QKeySequence, QIcon, QPixmap, QPainter, QColor


class PasswordVisibilityDelegate:
    def __init__(self, table):
        self.table = table
        self.visible_rows = set()

    def toggle_visibility(self, row, item):
        if row in self.visible_rows:
            self.visible_rows.discard(row)
        else:
            self.visible_rows.add(row)
        self.table.update_entry_display(row)


class SecureTable(QTreeWidget):
    itemCopyUsernameRequested = pyqtSignal(object)
    itemCopyPasswordRequested = pyqtSignal(object)
    itemCopyURLRequested = pyqtSignal(object)
    itemEditRequested = pyqtSignal(object)
    itemDeleteRequested = pyqtSignal(object)
    itemsDeleteRequested = pyqtSignal(list)
    itemShowPasswordRequested = pyqtSignal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setHeaderLabels(["Title", "Username", "URL", "Password", "Last Modified"])
        self.header().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.header().setStretchLastSection(True)
        self.header().setSectionsMovable(True)
        self.setSortingEnabled(True)
        self.sortByColumn(0, Qt.SortOrder.AscendingOrder)
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_context_menu)
        self.setIndentation(0)
        self.setRootIsDecorated(False)
        self.setUniformRowHeights(True)

        self._global_password_visible = False
        self._eye_icons = {}
        self._create_eye_icons()

        self.setColumnWidth(0, 180)
        self.setColumnWidth(1, 150)
        self.setColumnWidth(2, 180)
        self.setColumnWidth(3, 120)
        self.setColumnWidth(4, 100)

        self.installEventFilter(self)

    def _create_eye_icons(self):
        eye_open_pixmap = QPixmap(16, 16)
        eye_open_pixmap.fill(Qt.GlobalColor.transparent)
        painter = QPainter(eye_open_pixmap)
        painter.setPen(QColor(100, 100, 100))
        painter.drawEllipse(4, 4, 8, 8)
        painter.drawLine(8, 2, 8, 14)
        painter.drawLine(2, 8, 14, 8)
        painter.end()

        eye_closed_pixmap = QPixmap(16, 16)
        eye_closed_pixmap.fill(Qt.GlobalColor.transparent)
        painter = QPainter(eye_closed_pixmap)
        painter.setPen(QColor(100, 100, 100))
        painter.drawEllipse(4, 4, 8, 8)
        painter.drawLine(2, 2, 14, 14)
        painter.end()

        self._eye_icons['open'] = QIcon(eye_open_pixmap)
        self._eye_icons['closed'] = QIcon(eye_closed_pixmap)

    def mask_username(self, username: str) -> str:
        if not username:
            return ""
        if len(username) <= 4:
            return "••••"
        return username[:4] + "••••"

    def mask_password(self, password: str) -> str:
        if not password:
            return ""
        return "•" * len(password)

    def add_entry(self, entry: dict) -> QTreeWidgetItem:
        if self._global_password_visible:
            password_display = entry.get('password', '')
            username_display = entry.get('username', '')
        else:
            password_display = self.mask_password(entry.get('password', ''))
            username_display = self.mask_username(entry.get('username', ''))

        last_modified = entry.get('updated_at', entry.get('created_at', ''))
        if last_modified:
            last_modified = last_modified[:10] if len(last_modified) > 10 else last_modified

        item = QTreeWidgetItem([
            entry.get('title', ''),
            username_display,
            self.extract_domain(entry.get('url', '')),
            password_display,
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

    def update_entry_display(self, row):
        item = self.topLevelItem(row)
        if not item:
            return

        username = item.data(1, Qt.ItemDataRole.UserRole)
        password = item.data(3, Qt.ItemDataRole.UserRole)

        if self._global_password_visible:
            item.setText(1, username)
            item.setText(3, password)
        else:
            item.setText(1, self.mask_username(username))
            item.setText(3, self.mask_password(password))

    def refresh_all_displays(self):
        for i in range(self.topLevelItemCount()):
            self.update_entry_display(i)

    def set_global_password_visibility(self, visible: bool):
        self._global_password_visible = visible
        self.refresh_all_displays()

    def is_global_password_visible(self) -> bool:
        return self._global_password_visible

    def toggle_global_password_visibility(self):
        self.set_global_password_visibility(not self._global_password_visible)

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

    def get_selected_count(self) -> int:
        return len(self.selectedItems())

    def show_context_menu(self, position):
        selected_count = self.get_selected_count()
        item = self.itemAt(position)

        menu = QMenu()

        if selected_count == 1 and item:
            copy_menu = menu.addMenu("Copy")

            copy_username_action = QAction("Copy Username", self)
            copy_username_action.triggered.connect(lambda: self.itemCopyUsernameRequested.emit(item))
            copy_menu.addAction(copy_username_action)

            copy_password_action = QAction("Copy Password", self)
            copy_password_action.triggered.connect(lambda: self.itemCopyPasswordRequested.emit(item))
            copy_menu.addAction(copy_password_action)

            copy_url_action = QAction("Copy URL", self)
            copy_url_action.triggered.connect(lambda: self.itemCopyURLRequested.emit(item))
            copy_menu.addAction(copy_url_action)

            menu.addSeparator()

            show_password_action = QAction("Show/Hide Password", self)
            show_password_action.triggered.connect(lambda: self.itemShowPasswordRequested.emit(item))
            menu.addAction(show_password_action)

            menu.addSeparator()

            edit_action = QAction("Edit", self)
            edit_action.setShortcut(QKeySequence(Qt.Key.Key_F2))
            edit_action.triggered.connect(lambda: self.itemEditRequested.emit(item))
            menu.addAction(edit_action)

            delete_action = QAction("Delete", self)
            delete_action.setShortcut(QKeySequence(Qt.Key.Key_Delete))
            delete_action.triggered.connect(lambda: self.itemDeleteRequested.emit(item))
            menu.addAction(delete_action)

        elif selected_count > 1:
            copy_menu = menu.addMenu(f"Copy ({selected_count} items)")

            copy_usernames_action = QAction("Copy All Usernames", self)
            copy_usernames_action.triggered.connect(self._copy_all_usernames)
            copy_menu.addAction(copy_usernames_action)

            copy_passwords_action = QAction("Copy All Passwords", self)
            copy_passwords_action.triggered.connect(self._copy_all_passwords)
            copy_menu.addAction(copy_passwords_action)

            menu.addSeparator()

            delete_all_action = QAction(f"Delete {selected_count} Items", self)
            delete_all_action.triggered.connect(self._delete_all_selected)
            delete_all_action.setShortcut(QKeySequence(Qt.Key.Key_Delete))
            menu.addAction(delete_all_action)

        menu.addSeparator()

        toggle_visibility_action = QAction("Toggle Password Visibility (Ctrl+Shift+P)", self)
        toggle_visibility_action.triggered.connect(self.toggle_global_password_visibility)
        menu.addAction(toggle_visibility_action)

        if menu.actions():
            menu.exec(self.viewport().mapToGlobal(position))

    def _copy_all_usernames(self):
        selected_items = self.selectedItems()
        usernames = []
        for item in selected_items:
            username = item.data(1, Qt.ItemDataRole.UserRole)
            if username:
                usernames.append(username)
        if usernames:
            QApplication.clipboard().setText("\n".join(usernames))

    def _copy_all_passwords(self):
        selected_items = self.selectedItems()
        passwords = []
        for item in selected_items:
            password = item.data(3, Qt.ItemDataRole.UserRole)
            if password:
                passwords.append(password)
        if passwords:
            QApplication.clipboard().setText("\n".join(passwords))

    def _delete_all_selected(self):
        selected_ids = self.get_selected_entry_ids()
        if selected_ids:
            self.itemsDeleteRequested.emit(selected_ids)

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

    def remove_entries_by_ids(self, entry_ids: list) -> int:
        removed = 0
        for entry_id in entry_ids:
            if self.remove_entry_by_id(entry_id):
                removed += 1
        return removed

    def update_entry_in_table(self, entry: dict):
        item = self.get_item_by_id(entry.get('id', ''))
        if item:
            if self._global_password_visible:
                username_display = entry.get('username', '')
                password_display = entry.get('password', '')
            else:
                username_display = self.mask_username(entry.get('username', ''))
                password_display = self.mask_password(entry.get('password', ''))

            item.setText(0, entry.get('title', ''))
            item.setText(1, username_display)
            item.setText(2, self.extract_domain(entry.get('url', '')))
            item.setText(3, password_display)

            last_modified = entry.get('updated_at', entry.get('created_at', ''))
            if last_modified:
                last_modified = last_modified[:10] if len(last_modified) > 10 else last_modified
            item.setText(4, last_modified)

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

    def get_column_state(self) -> dict:
        state = {
            'column_widths': [],
            'column_order': [],
            'sort_column': self.header().sortIndicatorSection(),
            'sort_order': self.header().sortIndicatorOrder()
        }
        for i in range(self.columnCount()):
            state['column_widths'].append(self.columnWidth(i))
            state['column_order'].append(self.header().visualIndex(i))
        return state

    def set_column_state(self, state: dict):
        if 'column_widths' in state and len(state['column_widths']) == self.columnCount():
            for i, width in enumerate(state['column_widths']):
                if width > 50:
                    self.setColumnWidth(i, width)
        if 'column_order' in state and len(state['column_order']) == self.columnCount():
            for i, visual_index in enumerate(state['column_order']):
                self.header().moveSection(self.header().visualIndex(i), visual_index)
        if 'sort_column' in state and 'sort_order' in state:
            self.sortByColumn(state['sort_column'], state['sort_order'])

    def keyPressEvent(self, event):
        if event.key() == Qt.Key.Key_Delete:
            selected_ids = self.get_selected_entry_ids()
            if selected_ids:
                self.itemsDeleteRequested.emit(selected_ids)
        elif event.key() == Qt.Key.Key_F2:
            selected_items = self.selectedItems()
            if len(selected_items) == 1:
                self.itemEditRequested.emit(selected_items[0])
        elif event.key() == Qt.Key.Key_A and event.modifiers() == Qt.KeyboardModifier.ControlModifier:
            self.selectAll()
        elif event.key() == Qt.Key.Key_P and event.modifiers() == (
                Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.ShiftModifier):
            self.toggle_global_password_visibility()
        else:
            super().keyPressEvent(event)