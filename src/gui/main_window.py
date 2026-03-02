import sys
import os
import secrets
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout,
    QHBoxLayout, QPushButton, QLabel, QLineEdit,
    QTreeWidget, QTreeWidgetItem, QMessageBox, QDialog,
    QMenuBar, QMenu, QStatusBar, QDialogButtonBox,
    QFrame, QHeaderView, QFileDialog, QSpinBox
)
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QAction, QFont, QIcon

try:
    from src.core.state_manager import StateManager
    from src.core.events import EventBus
except ImportError:
    class StateManager:
        def __init__(self):
            self.is_locked = True
            self.current_user = None


    class EventBus:
        def publish(self, event_name, data=None):
            print(f"[EVENT] {event_name} {data or ''}")

state_manager = StateManager()
event_bus = EventBus()

from src.gui.widgets.password_entry import PasswordEntry
from src.gui.widgets.secure_table import SecureTable
from src.gui.widgets.audit_log_viewer import AuditLogViewer
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
        self.setWindowTitle("Первый запуск — создание хранилища")
        self.setFixedSize(480, 420)
        self.setModal(True)

        layout = QVBoxLayout()

        title = QLabel("Придумайте мастер-пароль:")
        title.setFont(QFont("Helvetica", 11))
        layout.addWidget(title, alignment=Qt.AlignmentFlag.AlignCenter)

        self.password_input = PasswordEntry()
        self.password_input.setFixedWidth(300)
        layout.addWidget(self.password_input, alignment=Qt.AlignmentFlag.AlignCenter)

        confirm_label = QLabel("Подтвердите пароль:")
        confirm_label.setFont(QFont("Helvetica", 11))
        layout.addWidget(confirm_label, alignment=Qt.AlignmentFlag.AlignCenter)

        self.confirm_input = PasswordEntry()
        self.confirm_input.setFixedWidth(300)
        layout.addWidget(self.confirm_input, alignment=Qt.AlignmentFlag.AlignCenter)

        db_label = QLabel("Выберите путь к базе данных:")
        db_label.setFont(QFont("Helvetica", 11))
        layout.addWidget(db_label, alignment=Qt.AlignmentFlag.AlignCenter)

        db_layout = QHBoxLayout()
        self.db_path_input = QLineEdit()
        self.db_path_input.setFixedWidth(250)
        db_layout.addWidget(self.db_path_input)
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self.browse_db_path)
        db_layout.addWidget(browse_btn)
        layout.addLayout(db_layout)

        settings_label = QLabel("Encryption settings (placeholder):")
        settings_label.setFont(QFont("Helvetica", 11))
        layout.addWidget(settings_label, alignment=Qt.AlignmentFlag.AlignCenter)

        self.iterations_spin = QSpinBox()
        self.iterations_spin.setRange(100000, 1000000)
        self.iterations_spin.setValue(600000)
        layout.addWidget(self.iterations_spin, alignment=Qt.AlignmentFlag.AlignCenter)

        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok |
                                      QDialogButtonBox.StandardButton.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box, alignment=Qt.AlignmentFlag.AlignCenter)

        self.setLayout(layout)
        self.password_input.entry.setFocus()

    def browse_db_path(self):
        path = QFileDialog.getSaveFileName(self, "Select DB Path", "", "SQLite DB (*.db)")[0]
        if path:
            self.db_path_input.setText(path)

    def get_data(self):
        if self.exec() == QDialog.DialogCode.Accepted:
            return (self.password_input.text(), self.confirm_input.text(),
                    self.db_path_input.text(), self.iterations_spin.value())
        return None, None, None, None


class CryptoSafeMainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CryptoSafe Manager")
        self.setMinimumSize(800, 500)
        self.resize(900, 600)

        self._create_menu()
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

    def _create_status_bar(self):
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.update_status()

    def _check_lock_state(self):
        for i in reversed(range(self.layout.count())):
            self.layout.itemAt(i).widget().setParent(None)

        db_path = "cryptosafe.db"

        if not os.path.exists(db_path):
            self._show_first_run_screen()
        elif state_manager.is_locked:
            self._show_locked_screen()
        else:
            self._show_unlocked_content()

        self.update_status()

    def _show_first_run_screen(self):
        frame = QFrame()
        layout = QVBoxLayout(frame)

        title = QLabel("Добро пожаловать в CryptoSafe Manager!")
        title.setFont(QFont("Helvetica", 20, QFont.Weight.Bold))
        layout.addWidget(title, alignment=Qt.AlignmentFlag.AlignCenter)

        message = QLabel(
            "Это первый запуск.\nСейчас приложение создаст зашифрованную базу данных.\n"
            "Придумайте надёжный мастер-пароль."
        )
        message.setFont(QFont("Helvetica", 12))
        message.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(message)

        create_btn = QPushButton("Создать хранилище")
        create_btn.setFixedWidth(200)
        create_btn.clicked.connect(self.first_run_setup)
        layout.addWidget(create_btn, alignment=Qt.AlignmentFlag.AlignCenter)

        layout.addStretch()
        self.layout.addWidget(frame)
        self.status_bar.showMessage("First run — setup required")

    def _show_locked_screen(self):
        frame = QFrame()
        layout = QVBoxLayout(frame)

        title = QLabel("CryptoSafe is Locked")
        title.setFont(QFont("Helvetica", 24, QFont.Weight.Bold))
        layout.addWidget(title, alignment=Qt.AlignmentFlag.AlignCenter)

        message = QLabel("Введите мастер-пароль для разблокировки хранилища")
        message.setFont(QFont("Helvetica", 12))
        layout.addWidget(message, alignment=Qt.AlignmentFlag.AlignCenter)

        unlock_btn = QPushButton("Разблокировать")
        unlock_btn.setFixedWidth(200)
        unlock_btn.clicked.connect(self.unlock_dialog)
        layout.addWidget(unlock_btn, alignment=Qt.AlignmentFlag.AlignCenter)

        layout.addStretch()
        self.layout.addWidget(frame)
        self.update_status()

    def _show_unlocked_content(self):
        self.table = SecureTable()
        self._fill_test_data()
        self.layout.addWidget(self.table)

    def _fill_test_data(self):
        test_data = [
            ("Google", "max123@gmail.com", "https://accounts.google.com", "Main email", "2025-02-10"),
            ("GitHub", "Ansa1r", "https://github.com/login", "Dev account", "2025-01-28"),
            ("Bank", "user456", "https://online.bank.ru", "Financial", "2024-12-15"),
        ]

        for item_data in test_data:
            item = QTreeWidgetItem(item_data)
            self.table.addTopLevelItem(item)

    def update_status(self):
        if state_manager.is_locked:
            text = "Locked | Vault protected"
        else:
            text = f"Unlocked | User: {state_manager.current_user or 'Unknown'}"
        self.status_bar.showMessage(text)

    def unlock_dialog(self):
        dialog = UnlockDialog(self)
        password = dialog.get_password()

        if password:
            if len(password) >= 4:
                from src.core.crypto.secure_memory import secure_wipe_str, secure_zero_bytes
                fake_key = secrets.token_bytes(32)
                secure_zero_bytes(fake_key)
                secure_wipe_str(password)

                state_manager.is_locked = False
                state_manager.current_user = "demo-user"
                event_bus.publish("UserLoggedIn", {"user": "demo-user"})

                self._check_lock_state()
            else:
                QMessageBox.critical(self, "Access denied", "Incorrect password")

    def first_run_setup(self):
        dialog = FirstRunDialog(self)
        password, confirm, db_path, iterations = dialog.get_data()

        if password is not None:
            if not password or not confirm:
                QMessageBox.warning(self, "Ошибка", "Пароль не может быть пустым")
                return

            if password != confirm:
                QMessageBox.critical(self, "Ошибка", "Пароли не совпадают")
                return

            if len(password) < 8:
                reply = QMessageBox.question(
                    self, "Слабый пароль",
                    "Рекомендуется использовать пароль минимум 8 символов. Продолжить?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                )
                if reply == QMessageBox.StandardButton.No:
                    return

            db_path = db_path or "cryptosafe.db"

            try:
                open(db_path, "a").close()
                QMessageBox.information(self, "Успех", f"Хранилище создано по пути {db_path}!\nIterations: {iterations}\nТеперь можно разблокировать.")
                self._check_lock_state()
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось создать файл базы:\n{e}")

    def new_vault(self):
        QMessageBox.information(self, "Action", "New Vault — not implemented yet")

    def open_vault(self):
        QMessageBox.information(self, "Action", "Open Vault — not implemented yet")

    def backup(self):
        QMessageBox.information(self, "Action", "Backup — stub")

    def add_entry(self):
        QMessageBox.information(self, "Action", "Add Entry — stub")

    def edit_entry(self):
        QMessageBox.information(self, "Action", "Edit Entry — stub")

    def delete_entry(self):
        QMessageBox.information(self, "Action", "Delete Entry — stub")

    def show_audit_log(self):
        viewer = AuditLogViewer(self)
        viewer.exec()

    def show_settings(self):
        dialog = SettingsDialog(self)
        dialog.exec()

    def show_about(self):
        QMessageBox.about(
            self, "About",
            "CryptoSafe Manager\nLaboratory work\nSprint 1 — Foundation"
        )

    def closeEvent(self, event):
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