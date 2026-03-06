from PyQt6.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QFormLayout, QLineEdit, QTextEdit, QPushButton, \
    QDialogButtonBox
from PyQt6.QtCore import Qt


class EntryDialog(QDialog):
    def __init__(self, parent=None, entry_data=None):
        super().__init__(parent)
        self.entry_data = entry_data
        self.setWindowTitle("Add Entry" if not entry_data else "Edit Entry")
        self.setMinimumWidth(500)

        layout = QVBoxLayout(self)

        form_layout = QFormLayout()

        self.title_edit = QLineEdit()
        self.title_edit.setPlaceholderText("e.g., Google, GitHub, Bank")
        form_layout.addRow("Title:", self.title_edit)

        self.username_edit = QLineEdit()
        self.username_edit.setPlaceholderText("username@example.com")
        form_layout.addRow("Username:", self.username_edit)

        self.password_edit = QLineEdit()
        self.password_edit.setPlaceholderText("Enter password")
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        password_layout = QHBoxLayout()
        password_layout.addWidget(self.password_edit)
        self.show_password_btn = QPushButton("Show")
        self.show_password_btn.setCheckable(True)
        self.show_password_btn.toggled.connect(self.toggle_password_visibility)
        password_layout.addWidget(self.show_password_btn)
        form_layout.addRow("Password:", password_layout)

        self.url_edit = QLineEdit()
        self.url_edit.setPlaceholderText("https://example.com")
        form_layout.addRow("URL:", self.url_edit)

        self.notes_edit = QTextEdit()
        self.notes_edit.setPlaceholderText("Additional notes...")
        self.notes_edit.setMaximumHeight(100)
        form_layout.addRow("Notes:", self.notes_edit)

        self.tags_edit = QLineEdit()
        self.tags_edit.setPlaceholderText("work, personal, finance")
        form_layout.addRow("Tags:", self.tags_edit)

        layout.addLayout(form_layout)

        if entry_data:
            self.load_entry_data()

        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

    def toggle_password_visibility(self, checked):
        if checked:
            self.password_edit.setEchoMode(QLineEdit.EchoMode.Normal)
            self.show_password_btn.setText("Hide")
        else:
            self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
            self.show_password_btn.setText("Show")

    def load_entry_data(self):
        self.title_edit.setText(self.entry_data.get('title', ''))
        self.username_edit.setText(self.entry_data.get('username', ''))
        self.password_edit.setText(self.entry_data.get('password', ''))
        self.url_edit.setText(self.entry_data.get('url', ''))
        self.notes_edit.setText(self.entry_data.get('notes', ''))
        self.tags_edit.setText(self.entry_data.get('tags', ''))

    def get_data(self):
        return {
            'title': self.title_edit.text().strip(),
            'username': self.username_edit.text().strip() or None,
            'password': self.password_edit.text(),
            'url': self.url_edit.text().strip() or None,
            'notes': self.notes_edit.toPlainText().strip() or None,
            'tags': self.tags_edit.text().strip() or None
        }