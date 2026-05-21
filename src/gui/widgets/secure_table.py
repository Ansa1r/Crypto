from PyQt6.QtWidgets import QTreeWidget, QTreeWidgetItem, QHeaderView, QMenu, QAbstractItemView, QApplication, \
    QProgressDialog
from PyQt6.QtCore import Qt, pyqtSignal, QTimer, QThread
from PyQt6.QtGui import QAction, QKeySequence


class LoadEntriesThread(QThread):
    chunk_loaded = pyqtSignal(list, int)
    finished = pyqtSignal()
    progress = pyqtSignal(int, int)

    def __init__(self, entries_data, chunk_size=100):
        super().__init__()
        self.entries_data = entries_data
        self.chunk_size = chunk_size
        self._is_running = True

    def run(self):
        total = len(self.entries_data)
        for i in range(0, total, self.chunk_size):
            if not self._is_running:
                break
            chunk = self.entries_data[i:i + self.chunk_size]
            self.chunk_loaded.emit(chunk, i)
            self.progress.emit(min(i + self.chunk_size, total), total)
            self.msleep(10)
        self.finished.emit()

    def stop(self):
        self._is_running = False


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
        self._all_entries = []
        self._visible_entries = []
        self._load_thread = None
        self._is_loading = False
        self._batch_update_timer = QTimer()
        self._batch_update_timer.setSingleShot(True)
        self._batch_update_timer.timeout.connect(self._apply_batch_update)
        self._pending_entries = []
        self._deferred_updates = []
        self._update_timer = QTimer()
        self._update_timer.setSingleShot(True)
        self._update_timer.timeout.connect(self._apply_deferred_updates)

        self.setColumnWidth(0, 180)
        self.setColumnWidth(1, 150)
        self.setColumnWidth(2, 180)
        self.setColumnWidth(3, 120)
        self.setColumnWidth(4, 100)

        self.setUpdatesEnabled(True)

        self.installEventFilter(self)

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

    def create_item_from_entry(self, entry: dict) -> QTreeWidgetItem:
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

    def load_entries_async(self, entries: list, parent_widget=None):
        if self._load_thread and self._load_thread.isRunning():
            self._load_thread.stop()
            self._load_thread.wait()

        self._all_entries = entries
        self._visible_entries = entries.copy()
        self.clear()

        if len(entries) > 500:
            self.setSortingEnabled(False)
            self._is_loading = True

            progress = None
            if parent_widget:
                progress = QProgressDialog("Loading entries...", "Cancel", 0, len(entries), parent_widget)
                progress.setWindowModality(Qt.WindowModality.WindowModal)
                progress.setMinimumDuration(200)

            self._load_thread = LoadEntriesThread(entries, chunk_size=100)

            def on_chunk_loaded(chunk, start_index):
                if progress and progress.wasCanceled():
                    self._load_thread.stop()
                    return
                for entry in chunk:
                    item = self.create_item_from_entry(entry)
                    self.addTopLevelItem(item)
                QApplication.processEvents()

            def on_progress(current, total):
                if progress:
                    progress.setValue(current)

            def on_finished():
                self._is_loading = False
                self.setSortingEnabled(True)
                if progress:
                    progress.close()

            self._load_thread.chunk_loaded.connect(on_chunk_loaded)
            self._load_thread.progress.connect(on_progress)
            self._load_thread.finished.connect(on_finished)
            self._load_thread.start()
        else:
            for entry in entries:
                item = self.create_item_from_entry(entry)
                self.addTopLevelItem(item)

    def load_entries_sync(self, entries: list):
        self.setUpdatesEnabled(False)
        self.clear()

        for entry in entries:
            item = self.create_item_from_entry(entry)
            self.addTopLevelItem(item)

        self.setUpdatesEnabled(True)

    def add_entry_fast(self, entry: dict):
        self._pending_entries.append(entry)
        if not self._batch_update_timer.isActive():
            self._batch_update_timer.start(50)

    def _apply_batch_update(self):
        if not self._pending_entries:
            return

        self.setUpdatesEnabled(False)
        for entry in self._pending_entries:
            item = self.create_item_from_entry(entry)
            self.addTopLevelItem(item)
            self._all_entries.append(entry)
            self._visible_entries.append(entry)
        self._pending_entries.clear()
        self.setUpdatesEnabled(True)

    def update_entry_deferred(self, entry: dict):
        self._deferred_updates.append(entry)
        if not self._update_timer.isActive():
            self._update_timer.start(100)

    def _apply_deferred_updates(self):
        if not self._deferred_updates:
            return

        self.setUpdatesEnabled(False)
        for entry in self._deferred_updates:
            self.update_entry_in_table(entry)
        self._deferred_updates.clear()
        self.setUpdatesEnabled(True)

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
        self.setUpdatesEnabled(False)
        for i in range(self.topLevelItemCount()):
            self.update_entry_display(i)
        self.setUpdatesEnabled(True)

    def set_global_password_visibility(self, visible: bool):
        self._global_password_visible = visible
        self.refresh_all_displays()

    def is_global_password_visible(self) -> bool:
        return self._global_password_visible

    def toggle_global_password_visibility(self):
        self.set_global_password_visibility(not self._global_password_visible)

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
            self._all_entries = [e for e in self._all_entries if e.get('id') != entry_id]
            self._visible_entries = [e for e in self._visible_entries if e.get('id') != entry_id]
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

            for i, e in enumerate(self._all_entries):
                if e.get('id') == entry.get('id'):
                    self._all_entries[i] = entry
                    break
            for i, e in enumerate(self._visible_entries):
                if e.get('id') == entry.get('id'):
                    self._visible_entries[i] = entry
                    break

    def clear_selection(self):
        self.clearSelection()

    def select_all(self):
        self.selectAll()

    def get_entry_count(self) -> int:
        return self.topLevelItemCount()

    def get_total_entry_count(self) -> int:
        return len(self._all_entries)

    def sort_by_column(self, column: int, order: Qt.SortOrder = None):
        if self._is_loading:
            return
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

    def filter_entries(self, filter_func):
        if self._is_loading:
            return
        self.setUpdatesEnabled(False)
        self.clear()
        filtered = [e for e in self._all_entries if filter_func(e)]
        self._visible_entries = filtered
        for entry in filtered:
            item = self.create_item_from_entry(entry)
            self.addTopLevelItem(item)
        self.setUpdatesEnabled(True)
        return len(filtered)

    def reset_filter(self):
        if self._is_loading:
            return
        self.setUpdatesEnabled(False)
        self.clear()
        self._visible_entries = self._all_entries.copy()
        for entry in self._all_entries:
            item = self.create_item_from_entry(entry)
            self.addTopLevelItem(item)
        self.setUpdatesEnabled(True)

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