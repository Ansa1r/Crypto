from PyQt6.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QFormLayout, QLineEdit, QTextEdit, QPushButton, \
    QDialogButtonBox, QLabel, QMessageBox, QComboBox, QSpinBox, QCheckBox, QGroupBox
from PyQt6.QtCore import Qt
from src.core.crypto.key_derivation import KeyDerivation
from src.core.vault.password_generator import PasswordGenerator
from src.gui.password_strength_indicator import PasswordStrengthIndicator


class EntryDialog(QDialog):
    def __init__(self, parent=None, entry_data=None):
        super().__init__(parent)
        self.entry_data = entry_data
        self.key_derivation = KeyDerivation()
        self.password_generator = PasswordGenerator()
        self.setWindowTitle("Add Entry" if not entry_data else "Edit Entry")
        self.setMinimumWidth(550)

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
        self.password_edit.textChanged.connect(self.on_password_changed)

        password_layout = QVBoxLayout()
        password_input_layout = QHBoxLayout()
        password_input_layout.addWidget(self.password_edit)

        self.show_password_btn = QPushButton("Show")
        self.show_password_btn.setCheckable(True)
        self.show_password_btn.toggled.connect(self.toggle_password_visibility)
        password_input_layout.addWidget(self.show_password_btn)

        self.generate_password_btn = QPushButton("Generate")
        self.generate_password_btn.clicked.connect(self.show_generator_dialog)
        password_input_layout.addWidget(self.generate_password_btn)

        password_layout.addLayout(password_input_layout)

        self.strength_indicator = PasswordStrengthIndicator()
        password_layout.addWidget(self.strength_indicator)

        self.strength_label = QLabel()
        self.strength_label.setStyleSheet("font-size: 10px;")
        password_layout.addWidget(self.strength_label)

        self.strength_feedback_label = QLabel()
        self.strength_feedback_label.setStyleSheet("font-size: 9px; color: gray;")
        self.strength_feedback_label.setWordWrap(True)
        password_layout.addWidget(self.strength_feedback_label)

        self.password_error_label = QLabel()
        self.password_error_label.setStyleSheet("color: red; font-size: 10px;")
        self.password_error_label.setWordWrap(True)
        password_layout.addWidget(self.password_error_label)

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

    def show_generator_dialog(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Generate Password")
        dialog.setMinimumWidth(400)

        layout = QVBoxLayout(dialog)

        length_layout = QHBoxLayout()
        length_layout.addWidget(QLabel("Length:"))
        length_spin = QSpinBox()
        length_spin.setRange(8, 64)
        length_spin.setValue(16)
        length_layout.addWidget(length_spin)
        length_layout.addStretch()
        layout.addLayout(length_layout)

        self.uppercase_cb = QCheckBox("Uppercase (A-Z)")
        self.uppercase_cb.setChecked(True)
        layout.addWidget(self.uppercase_cb)

        self.lowercase_cb = QCheckBox("Lowercase (a-z)")
        self.lowercase_cb.setChecked(True)
        layout.addWidget(self.lowercase_cb)

        self.digits_cb = QCheckBox("Digits (0-9)")
        self.digits_cb.setChecked(True)
        layout.addWidget(self.digits_cb)

        self.symbols_cb = QCheckBox("Symbols (!@#$%^&*)")
        self.symbols_cb.setChecked(True)
        layout.addWidget(self.symbols_cb)

        self.exclude_ambiguous_cb = QCheckBox("Exclude ambiguous characters (l, I, 1, O, 0)")
        self.exclude_ambiguous_cb.setChecked(True)
        layout.addWidget(self.exclude_ambiguous_cb)

        preview_label = QLabel()
        preview_label.setStyleSheet("font-family: monospace; background-color: #f0f0f0; padding: 8px;")
        preview_label.setWordWrap(True)
        layout.addWidget(preview_label)

        def update_preview():
            password = self.password_generator.generate(
                length=length_spin.value(),
                use_uppercase=self.uppercase_cb.isChecked(),
                use_lowercase=self.lowercase_cb.isChecked(),
                use_digits=self.digits_cb.isChecked(),
                use_symbols=self.symbols_cb.isChecked(),
                exclude_ambiguous=self.exclude_ambiguous_cb.isChecked(),
                min_score=0
            )
            preview_label.setText(f"Preview: {password}")

        length_spin.valueChanged.connect(update_preview)
        self.uppercase_cb.toggled.connect(update_preview)
        self.lowercase_cb.toggled.connect(update_preview)
        self.digits_cb.toggled.connect(update_preview)
        self.symbols_cb.toggled.connect(update_preview)
        self.exclude_ambiguous_cb.toggled.connect(update_preview)

        update_preview()

        gen_btn = QPushButton("Generate and Use")
        layout.addWidget(gen_btn)

        cancel_btn = QPushButton("Cancel")
        layout.addWidget(cancel_btn)

        def apply_generated():
            password = self.password_generator.generate(
                length=length_spin.value(),
                use_uppercase=self.uppercase_cb.isChecked(),
                use_lowercase=self.lowercase_cb.isChecked(),
                use_digits=self.digits_cb.isChecked(),
                use_symbols=self.symbols_cb.isChecked(),
                exclude_ambiguous=self.exclude_ambiguous_cb.isChecked()
            )
            self.password_edit.setText(password)
            dialog.accept()

        gen_btn.clicked.connect(apply_generated)
        cancel_btn.clicked.connect(dialog.reject)

        dialog.exec()

    def on_password_changed(self, text):
        if not text:
            self.strength_indicator.set_strength(0)
            self.strength_label.setText("")
            self.strength_feedback_label.setText("")
            self.password_error_label.setText("")
            return

        is_strong, details = self.password_generator.is_strong_enough(text)
        score = details['score']
        strength_label = self.password_generator.get_strength_label(score)

        self.strength_indicator.set_strength(score)
        self.strength_label.setText(f"Strength: {strength_label}")

        feedback_text = ""
        if details['feedback']['warning']:
            feedback_text += f"⚠️ {details['feedback']['warning']}\n"
        if details['feedback']['suggestions']:
            feedback_text += "💡 " + " ".join(details['feedback']['suggestions'][:2])
        self.strength_feedback_label.setText(feedback_text)

        if is_strong:
            self.password_error_label.setText("")
        else:
            self.password_error_label.setText("Password is too weak. Please use a stronger password.")

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

    def accept(self):
        password = self.password_edit.text()
        if password:
            is_strong, details = self.password_generator.is_strong_enough(password)
            if not is_strong:
                reply = QMessageBox.warning(
                    self,
                    "Weak Password",
                    f"Your password is {self.password_generator.get_strength_label(details['score']).lower()}.\n\n"
                    f"{details['feedback'].get('warning', '')}\n\n"
                    f"Are you sure you want to use this password?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No
                )
                if reply != QMessageBox.StandardButton.Yes:
                    return

        if not self.title_edit.text().strip():
            QMessageBox.warning(self, "Warning", "Title is required")
            return

        super().accept()