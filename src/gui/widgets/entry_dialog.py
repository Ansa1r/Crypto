from PyQt6.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QFormLayout, QLineEdit, QTextEdit, QPushButton, \
    QDialogButtonBox, QLabel, QMessageBox, QSpinBox, QCheckBox, QGroupBox, QCompleter, QMenu
from PyQt6.QtCore import Qt, QStringListModel
from src.core.crypto.key_derivation import KeyDerivation
from src.core.vault.password_generator import PasswordGenerator
from src.gui.password_strength_indicator import PasswordStrengthIndicator


class EntryDialog(QDialog):
    def __init__(self, parent=None, entry_data=None):
        super().__init__(parent)
        self.entry_data = entry_data
        self.key_derivation = KeyDerivation()
        self.password_generator = PasswordGenerator()
        self.username_suggestions = []
        self.setWindowTitle("Add Entry" if not entry_data else "Edit Entry")
        self.setMinimumWidth(600)

        layout = QVBoxLayout(self)

        form_layout = QFormLayout()

        self.title_edit = QLineEdit()
        self.title_edit.setPlaceholderText("e.g., Google, GitHub, Bank")
        self.title_edit.textChanged.connect(self.update_ok_button)
        form_layout.addRow("Title:", self.title_edit)

        self.username_edit = QLineEdit()
        self.username_edit.setPlaceholderText("username@example.com")
        self.username_edit.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.username_edit.customContextMenuRequested.connect(self.show_username_suggestions)
        form_layout.addRow("Username:", self.username_edit)

        password_group = QGroupBox("Password")
        password_layout = QVBoxLayout(password_group)

        password_input_layout = QHBoxLayout()
        self.password_edit = QLineEdit()
        self.password_edit.setPlaceholderText("Enter password")
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_edit.textChanged.connect(self.on_password_changed)
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

        form_layout.addRow(password_group)

        self.url_edit = QLineEdit()
        self.url_edit.setPlaceholderText("https://example.com")
        self.url_edit.textChanged.connect(self.on_url_changed)
        form_layout.addRow("URL:", self.url_edit)

        self.url_error_label = QLabel()
        self.url_error_label.setStyleSheet("color: red; font-size: 10px;")
        self.url_error_label.setWordWrap(True)
        form_layout.addRow("", self.url_error_label)

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
        self.ok_button = button_box.button(QDialogButtonBox.StandardButton.Ok)
        self.ok_button.clicked.disconnect()
        self.ok_button.clicked.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

        self.update_ok_button()

    def extract_domain_from_url(self, url):
        if not url:
            return None
        url_lower = url.lower().strip()
        if url_lower.startswith('https://'):
            url_lower = url_lower[8:]
        elif url_lower.startswith('http://'):
            url_lower = url_lower[7:]
        if url_lower.startswith('www.'):
            url_lower = url_lower[4:]
        domain = url_lower.split('/')[0].split('?')[0]
        if '.' in domain:
            parts = domain.split('.')
            if len(parts) >= 2:
                return parts[-2]
        return None

    def get_username_suggestions_for_domain(self, domain):
        suggestions = []
        domain_lower = domain.lower() if domain else ""

        domain_patterns = {
            'google': ['user@gmail.com', 'username@gmail.com', 'name@gmail.com'],
            'gmail': ['user@gmail.com', 'username@gmail.com', 'name@gmail.com'],
            'github': ['username', 'yourname', 'devusername'],
            'gitlab': ['username', 'yourname', 'devusername'],
            'facebook': ['user@facebook.com', 'name@facebook.com'],
            'fb': ['user@facebook.com', 'name@facebook.com'],
            'twitter': ['username', 'handle', 'user@twitter.com'],
            'x': ['username', 'handle', 'user@x.com'],
            'instagram': ['username', 'instaname', 'user@instagram.com'],
            'linkedin': ['name.surname', 'username@linkedin.com'],
            'amazon': ['user@amazon.com', 'username@amazon.com'],
            'apple': ['user@icloud.com', 'username@apple.com'],
            'icloud': ['user@icloud.com', 'username@icloud.com'],
            'microsoft': ['user@outlook.com', 'username@microsoft.com'],
            'outlook': ['user@outlook.com', 'username@outlook.com'],
            'hotmail': ['user@hotmail.com', 'username@hotmail.com'],
            'yahoo': ['user@yahoo.com', 'username@yahoo.com'],
            'reddit': ['username', 'reddituser'],
            'netflix': ['user@netflix.com', 'email@example.com'],
            'spotify': ['username', 'user@spotify.com'],
            'dropbox': ['user@dropbox.com', 'username@dropbox.com'],
            'slack': ['user@slack.com', 'username@slack.com'],
            'zoom': ['user@zoom.us', 'username@zoom.us'],
            'discord': ['username', 'user#1234'],
            'twitch': ['username', 'twitchuser'],
            'paypal': ['user@paypal.com', 'username@paypal.com'],
            'ebay': ['user@ebay.com', 'username@ebay.com'],
            'aliexpress': ['user@aliexpress.com', 'username@aliexpress.com'],
            'stackoverflow': ['username', 'user@stackoverflow.com'],
            'medium': ['username', 'user@medium.com'],
            'quora': ['username', 'user@quora.com'],
            'pinterest': ['username', 'user@pinterest.com'],
            'tumblr': ['username', 'user@tumblr.com'],
            'whatsapp': ['phone_number', 'username'],
            'telegram': ['username', 'phone_number'],
            'viber': ['phone_number', 'username'],
            'skype': ['username', 'live:username'],
            'steam': ['username', 'steamusername'],
            'epicgames': ['username', 'user@epicgames.com'],
            'battlenet': ['username', 'battletag'],
            'origin': ['username', 'user@origin.com'],
            'ubi': ['username', 'user@ubisoft.com'],
            'nintendo': ['username', 'user@nintendo.com'],
            'playstation': ['username', 'user@playstation.com'],
            'xbox': ['username', 'user@xbox.com']
        }

        for pattern, sugs in domain_patterns.items():
            if pattern in domain_lower:
                suggestions.extend(sugs)
                break

        if not suggestions:
            suggestions = [f'user@{domain}.com', f'username@{domain}.com', domain]

        return list(dict.fromkeys(suggestions))

    def show_username_suggestions(self, position):
        url = self.url_edit.text().strip()
        if not url:
            return

        domain = self.extract_domain_from_url(url)
        if not domain:
            return

        suggestions = self.get_username_suggestions_for_domain(domain)
        if not suggestions:
            return

        menu = QMenu(self)
        for suggestion in suggestions[:5]:
            action = menu.addAction(suggestion)
            action.triggered.connect(lambda checked, s=suggestion: self.username_edit.setText(s))
        menu.addSeparator()
        clear_action = menu.addAction("Clear")
        clear_action.triggered.connect(lambda: self.username_edit.clear())

        menu.exec(self.username_edit.mapToGlobal(position))

    def show_generator_dialog(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Generate Password")
        dialog.setMinimumWidth(500)
        dialog.setModal(True)

        layout = QVBoxLayout(dialog)

        length_layout = QHBoxLayout()
        length_layout.addWidget(QLabel("Password Length:"))
        length_spin = QSpinBox()
        length_spin.setRange(8, 64)
        length_spin.setValue(16)
        length_layout.addWidget(length_spin)
        length_layout.addStretch()
        layout.addLayout(length_layout)

        charsets_group = QGroupBox("Character Sets")
        charsets_layout = QVBoxLayout(charsets_group)

        self.gen_uppercase_cb = QCheckBox("Uppercase (A-Z)")
        self.gen_uppercase_cb.setChecked(True)
        charsets_layout.addWidget(self.gen_uppercase_cb)

        self.gen_lowercase_cb = QCheckBox("Lowercase (a-z)")
        self.gen_lowercase_cb.setChecked(True)
        charsets_layout.addWidget(self.gen_lowercase_cb)

        self.gen_digits_cb = QCheckBox("Digits (0-9)")
        self.gen_digits_cb.setChecked(True)
        charsets_layout.addWidget(self.gen_digits_cb)

        self.gen_symbols_cb = QCheckBox("Symbols (!@#$%^&*)")
        self.gen_symbols_cb.setChecked(True)
        charsets_layout.addWidget(self.gen_symbols_cb)

        layout.addWidget(charsets_group)

        self.exclude_ambiguous_cb = QCheckBox("Exclude ambiguous characters (l, I, 1, O, 0)")
        self.exclude_ambiguous_cb.setChecked(True)
        layout.addWidget(self.exclude_ambiguous_cb)

        preview_group = QGroupBox("Preview")
        preview_layout = QVBoxLayout(preview_group)

        self.preview_label = QLabel()
        self.preview_label.setStyleSheet("font-family: monospace; background-color: #f0f0f0; padding: 8px;")
        self.preview_label.setWordWrap(True)
        preview_layout.addWidget(self.preview_label)

        self.regenerate_btn = QPushButton("Regenerate")
        self.regenerate_btn.clicked.connect(lambda: self.update_preview(length_spin.value()))
        preview_layout.addWidget(self.regenerate_btn)

        layout.addWidget(preview_group)

        strength_group = QGroupBox("Password Strength")
        strength_layout = QVBoxLayout(strength_group)

        self.preview_strength_indicator = PasswordStrengthIndicator()
        strength_layout.addWidget(self.preview_strength_indicator)

        self.preview_strength_label = QLabel()
        self.preview_strength_label.setStyleSheet("font-size: 10px;")
        strength_layout.addWidget(self.preview_strength_label)

        self.preview_feedback_label = QLabel()
        self.preview_feedback_label.setStyleSheet("font-size: 9px; color: gray;")
        self.preview_feedback_label.setWordWrap(True)
        strength_layout.addWidget(self.preview_feedback_label)

        layout.addWidget(strength_group)

        button_layout = QHBoxLayout()
        use_btn = QPushButton("Use This Password")
        use_btn.clicked.connect(lambda: self.use_generated_password(self.preview_label.text(), dialog))
        button_layout.addWidget(use_btn)

        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(dialog.reject)
        button_layout.addWidget(cancel_btn)

        layout.addLayout(button_layout)

        self.update_preview(length_spin.value())

        length_spin.valueChanged.connect(self.update_preview)
        self.gen_uppercase_cb.toggled.connect(lambda: self.update_preview(length_spin.value()))
        self.gen_lowercase_cb.toggled.connect(lambda: self.update_preview(length_spin.value()))
        self.gen_digits_cb.toggled.connect(lambda: self.update_preview(length_spin.value()))
        self.gen_symbols_cb.toggled.connect(lambda: self.update_preview(length_spin.value()))
        self.exclude_ambiguous_cb.toggled.connect(lambda: self.update_preview(length_spin.value()))

        dialog.exec()

    def update_preview(self, length):
        try:
            password = self.password_generator.generate(
                length=length,
                use_uppercase=self.gen_uppercase_cb.isChecked(),
                use_lowercase=self.gen_lowercase_cb.isChecked(),
                use_digits=self.gen_digits_cb.isChecked(),
                use_symbols=self.gen_symbols_cb.isChecked(),
                exclude_ambiguous=self.exclude_ambiguous_cb.isChecked(),
                min_score=0
            )
            self.preview_label.setText(password)

            score, feedback = self.password_generator.analyze_strength(password)
            strength_label = self.password_generator.get_strength_label(score)

            self.preview_strength_indicator.set_strength(score)
            self.preview_strength_label.setText(f"Strength: {strength_label}")

            feedback_text = ""
            if feedback['warning']:
                feedback_text += f"Warning: {feedback['warning']}\n"
            if feedback['suggestions']:
                feedback_text += "Suggestion: " + " ".join(feedback['suggestions'][:2])
            self.preview_feedback_label.setText(feedback_text)

            if score >= 3:
                self.preview_feedback_label.setStyleSheet("font-size: 9px; color: green;")
            elif score >= 2:
                self.preview_feedback_label.setStyleSheet("font-size: 9px; color: orange;")
            else:
                self.preview_feedback_label.setStyleSheet("font-size: 9px; color: red;")

        except Exception as e:
            self.preview_label.setText(f"Error generating password: {str(e)}")

    def use_generated_password(self, password, dialog):
        if password and not password.startswith("Error"):
            self.password_edit.setText(password)
            dialog.accept()

    def on_password_changed(self, text):
        if not text:
            self.strength_indicator.set_strength(0)
            self.strength_label.setText("")
            self.strength_feedback_label.setText("")
            self.password_error_label.setText("")
            self.update_ok_button()
            return

        is_strong, details = self.password_generator.is_strong_enough(text)
        score = details['score']
        strength_label = self.password_generator.get_strength_label(score)

        self.strength_indicator.set_strength(score)
        self.strength_label.setText(f"Strength: {strength_label}")

        feedback_text = ""
        if details['feedback']['warning']:
            feedback_text += f"Warning: {details['feedback']['warning']}\n"
        if details['feedback']['suggestions']:
            feedback_text += "Suggestion: " + " ".join(details['feedback']['suggestions'][:2])
        self.strength_feedback_label.setText(feedback_text)

        if score >= 3:
            self.strength_feedback_label.setStyleSheet("font-size: 9px; color: green;")
            self.password_error_label.setText("")
        elif score >= 2:
            self.strength_feedback_label.setStyleSheet("font-size: 9px; color: orange;")
            self.password_error_label.setText("Password is moderate. Consider using a stronger password.")
        else:
            self.strength_feedback_label.setStyleSheet("font-size: 9px; color: red;")
            self.password_error_label.setText("Password is too weak. Please use a stronger password.")

        self.update_ok_button()

    def on_url_changed(self, text):
        if not text:
            self.url_error_label.setText("")
            self.update_ok_button()
            return

        if self.is_valid_url(text):
            self.url_error_label.setText("")
            self.url_error_label.setStyleSheet("color: green; font-size: 10px;")
            self.url_error_label.setText("Valid URL format")

            domain = self.extract_domain_from_url(text)
            if domain:
                suggestions = self.get_username_suggestions_for_domain(domain)
                if suggestions and not self.username_edit.text():
                    self.username_edit.setPlaceholderText(f"Try: {suggestions[0]}")
                else:
                    self.username_edit.setPlaceholderText("username@example.com")
        else:
            self.url_error_label.setStyleSheet("color: red; font-size: 10px;")
            self.url_error_label.setText("Invalid URL format. Example: https://example.com")
            self.username_edit.setPlaceholderText("username@example.com")
        self.update_ok_button()

    def is_valid_url(self, url):
        if not url:
            return True
        url_lower = url.lower().strip()
        if url_lower.startswith('https://') or url_lower.startswith('http://'):
            remaining = url_lower.split('://')[1]
            if remaining and len(remaining) >= 3 and '.' in remaining:
                return True
        return False

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
        self.on_url_changed(self.entry_data.get('url', ''))
        self.on_password_changed(self.entry_data.get('password', ''))

    def get_data(self):
        return {
            'title': self.title_edit.text().strip(),
            'username': self.username_edit.text().strip() or None,
            'password': self.password_edit.text(),
            'url': self.url_edit.text().strip() or None,
            'notes': self.notes_edit.toPlainText().strip() or None,
            'tags': self.tags_edit.text().strip() or None
        }

    def update_ok_button(self):
        title_valid = bool(self.title_edit.text().strip())
        url_valid = self.is_valid_url(self.url_edit.text().strip())
        password_valid = bool(self.password_edit.text())
        self.ok_button.setEnabled(title_valid and url_valid and password_valid)

    def accept(self):
        title = self.title_edit.text().strip()
        if not title:
            QMessageBox.warning(self, "Warning", "Title is required")
            return

        url = self.url_edit.text().strip()
        if url and not self.is_valid_url(url):
            QMessageBox.warning(self, "Warning", "Please enter a valid URL (starting with http:// or https://)")
            return

        password = self.password_edit.text()
        if not password:
            QMessageBox.warning(self, "Warning", "Password is required")
            return

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

        super().accept()