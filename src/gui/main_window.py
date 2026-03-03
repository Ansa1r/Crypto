import sys
import os
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout,
    QHBoxLayout, QPushButton, QLabel, QLineEdit,
    QTreeWidget, QTreeWidgetItem, QMessageBox, QDialog,
    QMenuBar, QMenu, QStatusBar, QDialogButtonBox,
    QFrame, QHeaderView, QFileDialog, QSpinBox
)
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QAction, QFont

try:
    from src.core.state_manager import StateManager
    from src.core.events import EventBus
    from src.database.db import (
        init_db, add_vault_entry, get_all_vault_entries,
        update_vault_entry, delete_vault_entry, search_vault_entries,
        add_audit_log, set_master_password, verify_master_password,
        has_master_password
    )
except ImportError:
    class StateManager:
        def __init__(self):
            self.is_locked = True
            self.current_user = None


    class EventBus:
        def publish(self, event_name, data=None):
            print(f"[EVENT] {event_name} {data or ''}")


    def init_db(*args, **kwargs):
        pass


    def add_vault_entry(*args, **kwargs):
        return 1


    def get_all_vault_entries(*args, **kwargs):
        return []


    def update_vault_entry(*args, **kwargs):
        return True


    def delete_vault_entry(*args, **kwargs):
        return True


    def search_vault_entries(*args, **kwargs):
        return []


    def add_audit_log(*args, **kwargs):
        return 1


    def set_master_password(*args, **kwargs):
        pass


    def verify_master_password(*args, **kwargs):
        return False


    def has_master_password(*args, **kwargs):
        return False

state_manager = StateManager()
event_bus = EventBus()

from src.gui.widgets.password_entry import PasswordEntry
from src.gui.widgets.secure_table import SecureTable
from src.gui.widgets.audit_log_viewer import AuditLogViewer
from src.gui.widgets.entry_dialog import EntryDialog
from src.gui.settings_dialog import SettingsDialog


class UnlockDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Unlock Vault")
        self.setFixedSize(420, 220)
        self.setModal(True)

        layout = QVBoxLayout()

        label = QLabel("Enter master password:")
        label.setFont(QFont("Helvetica", 11))
        layout.addWidget(label, alignment=Qt.AlignmentFlag.AlignCenter)

        self.password_input = PasswordEntry()
        self.password_input.setFixedWidth(300)
        layout.addWidget(self.password_input, alignment=Qt.AlignmentFlag.AlignCenter)

        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok |
                                      QDialogButtonBox.StandardButton.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box, alignment=Qt.AlignmentFlag.AlignCenter)

        self.setLayout(layout)
        self.password_input.entry.setFocus()

    def get_password(self):
        return self.password_input.text() if self.exec() == QDialog.DialogCode.Accepted else None


class FirstRunDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("First Run - Create Vault")
        self.setFixedSize(480, 350)
        self.setModal(True)

        layout = QVBoxLayout()

        title = QLabel("Create Master Password:")
        title.setFont(QFont("Helvetica", 11))
        layout.addWidget(title, alignment=Qt.AlignmentFlag.AlignCenter)

        self.password_input = PasswordEntry()
        self.password_input.setFixedWidth(300)
        layout.addWidget(self.password_input, alignment=Qt.AlignmentFlag.AlignCenter)

        confirm_label = QLabel("Confirm Password:")
        confirm_label.setFont(QFont("Helvetica", 11))
        layout.addWidget(confirm_label, alignment=Qt.AlignmentFlag.AlignCenter)

        self.confirm_input = PasswordEntry()
        self.confirm_input.setFixedWidth(300)
        layout.addWidget(self.confirm_input, alignment=Qt.AlignmentFlag.AlignCenter)

        db_label = QLabel("Database Location:")
        db_label.setFont(QFont("Helvetica", 11))
        layout.addWidget(db_label, alignment=Qt.AlignmentFlag.AlignCenter)

        db_layout = QHBoxLayout()
        self.db_path_input = QLineEdit()
        self.db_path_input.setText(os.path.join(os.path.expanduser("~"), "cryptosafe.db"))
        self.db_path_input.setFixedWidth(250)
        db_layout.addWidget(self.db_path_input)
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self.browse_db_path)
        db_layout.addWidget(browse_btn)
        layout.addLayout(db_layout)

        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok |
                                      QDialogButtonBox.StandardButton.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box, alignment=Qt.AlignmentFlag.AlignCenter)

        self.setLayout(layout)
        self.password_input.entry.setFocus()

    def browse_db_path(self):
        path = QFileDialog.getSaveFileName(self, "Select DB Path", os.path.expanduser("~"), "SQLite DB (*.db)")[0]
        if path:
            if not path.endswith('.db'):
                path += '.db'
            self.db_path_input.setText(path)

    def get_data(self):
        if self.exec() == QDialog.DialogCode.Accepted:
            return (self.password_input.text(), self.confirm_input.text(), self.db_path_input.text())
        return None, None, None


class CryptoSafeMainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CryptoSafe Manager")
        self.setMinimumSize(800, 500)
        self.resize(900, 600)

        self.current_db_path = None
        self.current_entries = []
        self.max_attempts = 3
        self.attempts = 0

        self._create_menu()
        self._create_toolbar()
        self._create_status_bar()

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)

        self._check_lock_state()

    def _create_menu(self):
        menubar = self.menuBar()

        file_menu = menubar.addMenu("File")

        new_vault_action = QAction("New Vault...", self)
        new_vault_action.triggered.connect(self.new_vault)
        file_menu.addAction(new_vault_action)

        open_vault_action = QAction("Open Vault...", self)
        open_vault_action.triggered.connect(self.open_vault)
        file_menu.addAction(open_vault_action)

        file_menu.addSeparator()

        backup_action = QAction("Backup...", self)
        backup_action.triggered.connect(self.backup)
        file_menu.addAction(backup_action)

        restore_action = QAction("Restore...", self)
        restore_action.triggered.connect(self.restore)
        file_menu.addAction(restore_action)

        file_menu.addSeparator()

        lock_action = QAction("Lock Vault", self)
        lock_action.triggered.connect(self.lock_vault)
        file_menu.addAction(lock_action)

        file_menu.addSeparator()

        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        edit_menu = menubar.addMenu("Edit")

        add_entry_action = QAction("Add Entry...", self)
        add_entry_action.triggered.connect(self.add_entry)
        edit_menu.addAction(add_entry_action)

        edit_entry_action = QAction("Edit Selected", self)
        edit_entry_action.triggered.connect(self.edit_entry)
        edit_menu.addAction(edit_entry_action)

        delete_entry_action = QAction("Delete Selected", self)
        delete_entry_action.triggered.connect(self.delete_entry)
        edit_menu.addAction(delete_entry_action)

        view_menu = menubar.addMenu("View")

        audit_log_action = QAction("Show Audit Log", self)
        audit_log_action.triggered.connect(self.show_audit_log)
        view_menu.addAction(audit_log_action)

        settings_action = QAction("Settings...", self)
        settings_action.triggered.connect(self.show_settings)
        view_menu.addAction(settings_action)

        help_menu = menubar.addMenu("Help")

        about_action = QAction("About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

    def _create_toolbar(self):
        toolbar = self.addToolBar("Main")
        toolbar.setIconSize(QSize(16, 16))

        add_action = QAction("Add Entry", self)
        add_action.triggered.connect(self.add_entry)
        toolbar.addAction(add_action)

        edit_action = QAction("Edit", self)
        edit_action.triggered.connect(self.edit_entry)
        toolbar.addAction(edit_action)

        delete_action = QAction("Delete", self)
        delete_action.triggered.connect(self.delete_entry)
        toolbar.addAction(delete_action)

        toolbar.addSeparator()

        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Search...")
        self.search_box.setMaximumWidth(200)
        self.search_box.textChanged.connect(self.search_entries)
        toolbar.addWidget(self.search_box)

    def _create_status_bar(self):
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.update_status()

    def _check_lock_state(self):
        for i in reversed(range(self.layout.count())):
            widget = self.layout.itemAt(i).widget()
            if widget:
                widget.setParent(None)

        if not self.current_db_path or not os.path.exists(self.current_db_path):
            self._show_first_run_screen()
        elif state_manager.is_locked:
            self._show_locked_screen()
        else:
            self._show_unlocked_content()
            self.load_entries()

        self.update_status()

    def _show_first_run_screen(self):
        frame = QFrame()
        layout = QVBoxLayout(frame)

        title = QLabel("Welcome to CryptoSafe Manager!")
        title.setFont(QFont("Helvetica", 20, QFont.Weight.Bold))
        layout.addWidget(title, alignment=Qt.AlignmentFlag.AlignCenter)

        message = QLabel(
            "This is your first run.\nThe application will create an encrypted database.\n"
            "Create a strong master password to continue."
        )
        message.setFont(QFont("Helvetica", 12))
        message.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(message)

        create_btn = QPushButton("Create Vault")
        create_btn.setFixedWidth(200)
        create_btn.clicked.connect(self.first_run_setup)
        layout.addWidget(create_btn, alignment=Qt.AlignmentFlag.AlignCenter)

        layout.addStretch()
        self.layout.addWidget(frame)
        self.status_bar.showMessage("First run - setup required")

    def _show_locked_screen(self):
        frame = QFrame()
        layout = QVBoxLayout(frame)

        title = QLabel("CryptoSafe is Locked")
        title.setFont(QFont("Helvetica", 24, QFont.Weight.Bold))
        layout.addWidget(title, alignment=Qt.AlignmentFlag.AlignCenter)

        message = QLabel("Enter master password to unlock the vault")
        message.setFont(QFont("Helvetica", 12))
        layout.addWidget(message, alignment=Qt.AlignmentFlag.AlignCenter)

        unlock_btn = QPushButton("Unlock")
        unlock_btn.setFixedWidth(200)
        unlock_btn.clicked.connect(self.unlock_dialog)
        layout.addWidget(unlock_btn, alignment=Qt.AlignmentFlag.AlignCenter)

        self.attempts_label = QLabel("")
        self.attempts_label.setFont(QFont("Helvetica", 10))
        self.attempts_label.setStyleSheet("color: red;")
        layout.addWidget(self.attempts_label, alignment=Qt.AlignmentFlag.AlignCenter)

        layout.addStretch()
        self.layout.addWidget(frame)
        self.update_status()

    def _show_unlocked_content(self):
        self.table = SecureTable()
        self.table.setColumnCount(5)
        self.table.setHeaderLabels(["Title", "Username", "URL", "Tags", "Last Updated"])
        self.table.itemDoubleClicked.connect(self.edit_entry)
        self.layout.addWidget(self.table)

    def load_entries(self):
        if not self.current_db_path or not os.path.exists(self.current_db_path):
            return

        self.current_entries = get_all_vault_entries(self.current_db_path)
        self.table.clear()
        self.table.setHeaderLabels(["Title", "Username", "URL", "Tags", "Last Updated"])

        for entry in self.current_entries:
            item = QTreeWidgetItem([
                entry.get('title', ''),
                entry.get('username', ''),
                entry.get('url', ''),
                entry.get('tags', ''),
                entry.get('updated_at', '')[:10] if entry.get('updated_at') else ''
            ])
            item.setData(0, Qt.ItemDataRole.UserRole, entry['id'])
            self.table.addTopLevelItem(item)

        self.status_bar.showMessage(f"Loaded {len(self.current_entries)} entries")

    def search_entries(self, text):
        if not self.current_db_path or not text:
            self.load_entries()
            return

        results = search_vault_entries(text, self.current_db_path)
        self.table.clear()
        self.table.setHeaderLabels(["Title", "Username", "URL", "Tags", "Last Updated"])

        for entry in results:
            item = QTreeWidgetItem([
                entry.get('title', ''),
                entry.get('username', ''),
                entry.get('url', ''),
                entry.get('tags', ''),
                entry.get('updated_at', '')[:10] if entry.get('updated_at') else ''
            ])
            item.setData(0, Qt.ItemDataRole.UserRole, entry['id'])
            self.table.addTopLevelItem(item)

        self.status_bar.showMessage(f"Found {len(results)} entries")

    def update_status(self):
        if state_manager.is_locked:
            text = "🔒 Locked | Vault protected"
        else:
            text = f"🔓 Unlocked | User: {state_manager.current_user or 'Unknown'}"
            if self.current_db_path:
                text += f" | DB: {os.path.basename(self.current_db_path)}"
        self.status_bar.showMessage(text)

    def unlock_dialog(self):
        if not has_master_password(self.current_db_path):
            QMessageBox.critical(self, "Error", "No master password set for this vault")
            return

        dialog = UnlockDialog(self)
        password = dialog.get_password()

        if password:
            if verify_master_password(password, self.current_db_path):
                self.attempts = 0
                state_manager.is_locked = False
                state_manager.current_user = "user"
                event_bus.publish("UserLoggedIn", {"user": "user"})
                add_audit_log("UserLoggedIn", details="User unlocked vault", db_path=self.current_db_path)
                self._check_lock_state()
            else:
                self.attempts += 1
                remaining = self.max_attempts - self.attempts

                if remaining <= 0:
                    QMessageBox.critical(self, "Access Denied",
                                         "Maximum login attempts exceeded.\nThe application will close.")
                    self.close()
                else:
                    if hasattr(self, 'attempts_label'):
                        self.attempts_label.setText(f"Invalid password. {remaining} attempts remaining.")

                    QMessageBox.warning(self, "Access Denied",
                                        f"Invalid password. {remaining} attempts remaining.")

                    self.unlock_dialog()

    def first_run_setup(self):
        dialog = FirstRunDialog(self)
        password, confirm, db_path = dialog.get_data()

        if password is not None:
            if not password or not confirm:
                QMessageBox.warning(self, "Error", "Password cannot be empty")
                return

            if password != confirm:
                QMessageBox.critical(self, "Error", "Passwords do not match")
                return

            if len(password) < 4:
                reply = QMessageBox.question(
                    self, "Weak Password",
                    "It is recommended to use at least 4 characters. Continue?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                )
                if reply == QMessageBox.StandardButton.No:
                    return

            try:
                self.current_db_path = db_path
                init_db(db_path)

                set_master_password(password, db_path)

                state_manager.is_locked = False
                state_manager.current_user = "user"

                add_audit_log("VaultCreated", details=f"New vault created at {db_path}", db_path=db_path)

                QMessageBox.information(self, "Success", f"Vault created successfully!\nLocation: {db_path}")
                self._check_lock_state()

            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to create database:\n{str(e)}")

    def lock_vault(self):
        state_manager.is_locked = True
        state_manager.current_user = None
        add_audit_log("UserLoggedOut", details="User locked vault", db_path=self.current_db_path)
        self._check_lock_state()

    def new_vault(self):
        path = QFileDialog.getSaveFileName(self, "Create New Vault", os.path.expanduser("~"), "SQLite DB (*.db)")[0]
        if path:
            if not path.endswith('.db'):
                path += '.db'

            dialog = FirstRunDialog(self)
            password, confirm, _ = dialog.get_data()

            if password and password == confirm and len(password) >= 4:
                try:
                    self.current_db_path = path
                    init_db(path)
                    set_master_password(password, path)
                    state_manager.is_locked = False
                    state_manager.current_user = "user"
                    add_audit_log("VaultCreated", details=f"New vault created at {path}", db_path=path)
                    self._check_lock_state()
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Failed to create vault:\n{str(e)}")

    def open_vault(self):
        path = QFileDialog.getOpenFileName(self, "Open Vault", os.path.expanduser("~"), "SQLite DB (*.db)")[0]
        if path:
            self.current_db_path = path
            state_manager.is_locked = True
            self.attempts = 0
            self._check_lock_state()

    def backup(self):
        if not self.current_db_path:
            QMessageBox.warning(self, "Warning", "No vault is open")
            return

        backup_path = QFileDialog.getSaveFileName(self, "Backup Vault", os.path.expanduser("~"), "SQLite DB (*.db)")[0]
        if backup_path:
            try:
                from src.database.db import backup_db
                backup_db(backup_path, self.current_db_path)
                add_audit_log("VaultBackedUp", details=f"Backed up to {backup_path}", db_path=self.current_db_path)
                QMessageBox.information(self, "Success", "Backup created successfully")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Backup failed:\n{str(e)}")

    def restore(self):
        if not self.current_db_path:
            QMessageBox.warning(self, "Warning", "No vault is open")
            return

        backup_path = \
        QFileDialog.getOpenFileName(self, "Restore from Backup", os.path.expanduser("~"), "SQLite DB (*.db)")[0]
        if backup_path:
            reply = QMessageBox.question(
                self, "Confirm Restore",
                "This will overwrite your current vault. Continue?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.Yes:
                try:
                    from src.database.db import restore_db
                    restore_db(backup_path, self.current_db_path)
                    add_audit_log("VaultRestored", details=f"Restored from {backup_path}", db_path=self.current_db_path)
                    self.load_entries()
                    QMessageBox.information(self, "Success", "Vault restored successfully")
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Restore failed:\n{str(e)}")

    def add_entry(self):
        if state_manager.is_locked:
            QMessageBox.warning(self, "Warning", "Please unlock the vault first")
            return

        dialog = EntryDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            data = dialog.get_data()
            if not data['title']:
                QMessageBox.warning(self, "Warning", "Title is required")
                return

            try:
                entry_id = add_vault_entry(
                    title=data['title'],
                    username=data['username'],
                    password=data['password'],
                    url=data['url'],
                    notes=data['notes'],
                    tags=data['tags'],
                    db_path=self.current_db_path
                )
                add_audit_log("EntryAdded", entry_id, f"Added entry: {data['title']}", db_path=self.current_db_path)
                event_bus.publish("EntryAdded", {"id": entry_id, "title": data['title']})
                self.load_entries()
                QMessageBox.information(self, "Success", "Entry added successfully")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to add entry:\n{str(e)}")

    def edit_entry(self):
        if state_manager.is_locked:
            QMessageBox.warning(self, "Warning", "Please unlock the vault first")
            return

        selected = self.table.selectedItems()
        if not selected:
            QMessageBox.warning(self, "Warning", "Please select an entry to edit")
            return

        entry_id = selected[0].data(0, Qt.ItemDataRole.UserRole)
        entry = next((e for e in self.current_entries if e['id'] == entry_id), None)

        if not entry:
            return

        dialog = EntryDialog(self, entry)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            data = dialog.get_data()
            try:
                update_vault_entry(
                    entry_id=entry_id,
                    title=data['title'],
                    username=data['username'],
                    password=data['password'],
                    url=data['url'],
                    notes=data['notes'],
                    tags=data['tags'],
                    db_path=self.current_db_path
                )
                add_audit_log("EntryUpdated", entry_id, f"Updated entry: {data['title']}", db_path=self.current_db_path)
                event_bus.publish("EntryUpdated", {"id": entry_id, "title": data['title']})
                self.load_entries()
                QMessageBox.information(self, "Success", "Entry updated successfully")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to update entry:\n{str(e)}")

    def delete_entry(self):
        if state_manager.is_locked:
            QMessageBox.warning(self, "Warning", "Please unlock the vault first")
            return

        selected = self.table.selectedItems()
        if not selected:
            QMessageBox.warning(self, "Warning", "Please select an entry to delete")
            return

        entry_id = selected[0].data(0, Qt.ItemDataRole.UserRole)
        entry = next((e for e in self.current_entries if e['id'] == entry_id), None)

        if not entry:
            return

        reply = QMessageBox.question(
            self, "Confirm Delete",
            f"Are you sure you want to delete '{entry['title']}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            try:
                delete_vault_entry(entry_id, self.current_db_path)
                add_audit_log("EntryDeleted", entry_id, f"Deleted entry: {entry['title']}",
                              db_path=self.current_db_path)
                event_bus.publish("EntryDeleted", {"id": entry_id, "title": entry['title']})
                self.load_entries()
                QMessageBox.information(self, "Success", "Entry deleted successfully")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to delete entry:\n{str(e)}")

    def show_audit_log(self):
        viewer = AuditLogViewer(self, self.current_db_path)
        viewer.exec()

    def show_settings(self):
        dialog = SettingsDialog(self)
        dialog.exec()

    def show_about(self):
        QMessageBox.about(
            self, "About CryptoSafe Manager",
            "CryptoSafe Manager\nVersion 1.0 (Sprint 1)\n\n"
            "A secure password manager with modular architecture.\n"
            "Developed as a laboratory work project."
        )

    def closeEvent(self, event):
        if self.current_db_path and not state_manager.is_locked:
            add_audit_log("ApplicationClosed", details="User closed application", db_path=self.current_db_path)

        reply = QMessageBox.question(
            self, "Quit",
            "Do you want to quit CryptoSafe?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            event.accept()
        else:
            event.ignore()


def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')

    window = CryptoSafeMainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()