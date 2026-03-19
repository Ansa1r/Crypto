from PyQt6.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QProgressBar, \
    QMessageBox, QDialogButtonBox
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont


class ChangePasswordWorker(QThread):
    progress = pyqtSignal(int)
    status = pyqtSignal(str)
    finished = pyqtSignal(bool, str)

    def __init__(self, key_manager, old_password, new_password, db_path, crypto_service):
        super().__init__()
        self.key_manager = key_manager
        self.old_password = old_password
        self.new_password = new_password
        self.db_path = db_path
        self.crypto_service = crypto_service
        self.success = False
        self.error_message = ""

    def run(self):
        try:
            from src.database.db import get_connection, get_all_vault_entries, update_vault_entry

            with get_connection(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT key_data FROM key_store 
                    WHERE key_type = 'auth_hash' 
                    AND username = 'default'
                    ORDER BY created_at DESC LIMIT 1
                """)
                auth_hash_row = cursor.fetchone()

                cursor.execute("""
                    SELECT key_data FROM key_store 
                    WHERE key_type = 'pbkdf2_salt' 
                    AND username = 'default'
                    ORDER BY created_at DESC LIMIT 1
                """)
                salt_row = cursor.fetchone()

                if not auth_hash_row or not salt_row:
                    self.finished.emit(False, "Authentication data not found")
                    return

                auth_hash = auth_hash_row['key_data'].decode('utf-8')
                pbkdf2_salt = salt_row['key_data']

                if not self.key_manager.verify_current_password(self.old_password, auth_hash):
                    self.finished.emit(False, "Current password is incorrect")
                    return

                entries = get_all_vault_entries(self.db_path)
                total = len(entries)

                if total == 0:
                    self.key_manager.change_master_password(
                        self.old_password, self.new_password,
                        auth_hash, pbkdf2_salt, self.db_path,
                        self.crypto_service, "default"
                    )
                    self.finished.emit(True, "Password changed successfully")
                    return

                old_key = self.key_manager.get_encryption_key()
                new_key = self.key_manager.derive_new_key(self.new_password, pbkdf2_salt)

                conn.execute("BEGIN TRANSACTION")

                try:
                    for i, entry in enumerate(entries):
                        if entry.get('encrypted_password'):
                            try:
                                decrypted = self.crypto_service.decrypt(entry['encrypted_password'])
                                reencrypted = self.crypto_service.encrypt(decrypted)
                                update_vault_entry(
                                    entry['id'],
                                    encrypted_password=reencrypted,
                                    db_path=self.db_path
                                )
                            except Exception as e:
                                conn.execute("ROLLBACK")
                                self.finished.emit(False, f"Failed to re-encrypt entry {entry['id']}: {str(e)}")
                                return

                        progress = int((i + 1) / total * 100)
                        self.progress.emit(progress)
                        self.status.emit(f"Re-encrypting entries: {i + 1}/{total}")

                    new_auth_hash, new_auth_params = self.key_manager.key_derivation.create_auth_hash(self.new_password)
                    new_encryption_params = self.key_manager.key_derivation.create_encryption_params()

                    cursor.execute("""
                        DELETE FROM key_store 
                        WHERE key_type IN ('auth_hash', 'auth_params', 'encryption_params') 
                        AND username = 'default'
                    """)

                    cursor.execute("""
                        INSERT INTO key_store (key_type, key_data, params, username)
                        VALUES (?, ?, ?, ?)
                    """, ('auth_hash', new_auth_hash.encode('utf-8'), str(new_auth_params), 'default'))

                    cursor.execute("""
                        INSERT INTO key_store (key_type, key_data, params, username)
                        VALUES (?, ?, ?, ?)
                    """, ('auth_params', str(new_auth_params).encode('utf-8'), None, 'default'))

                    cursor.execute("""
                        INSERT INTO key_store (key_type, key_data, params, username)
                        VALUES (?, ?, ?, ?)
                    """, ('encryption_params', str(new_encryption_params).encode('utf-8'), None, 'default'))

                    conn.execute("COMMIT")
                    self.key_manager.lock()
                    self.finished.emit(True,
                                       "Password changed successfully. Please unlock the vault with your new password.")

                except Exception as e:
                    conn.execute("ROLLBACK")
                    self.finished.emit(False, f"Error during password change: {str(e)}")

        except Exception as e:
            self.finished.emit(False, f"Unexpected error: {str(e)}")


class ChangePasswordDialog(QDialog):
    def __init__(self, parent=None, key_manager=None, db_path=None, crypto_service=None):
        super().__init__(parent)
        self.key_manager = key_manager
        self.db_path = db_path
        self.crypto_service = crypto_service
        self.worker = None

        self.setWindowTitle("Change Master Password")
        self.setFixedSize(500, 400)
        self.setModal(True)

        layout = QVBoxLayout()

        title = QLabel("Change Master Password")
        title.setFont(QFont("Helvetica", 14, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        form_layout = QVBoxLayout()

        self.current_password_label = QLabel("Current Password:")
        self.current_password_label.setFont(QFont("Helvetica", 10))
        form_layout.addWidget(self.current_password_label)

        self.current_password = QLineEdit()
        self.current_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.current_password.setMinimumHeight(30)
        form_layout.addWidget(self.current_password)

        self.new_password_label = QLabel("New Password:")
        self.new_password_label.setFont(QFont("Helvetica", 10))
        form_layout.addWidget(self.new_password_label)

        self.new_password = QLineEdit()
        self.new_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.new_password.setMinimumHeight(30)
        form_layout.addWidget(self.new_password)

        self.confirm_password_label = QLabel("Confirm New Password:")
        self.confirm_password_label.setFont(QFont("Helvetica", 10))
        form_layout.addWidget(self.confirm_password_label)

        self.confirm_password = QLineEdit()
        self.confirm_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_password.setMinimumHeight(30)
        form_layout.addWidget(self.confirm_password)

        self.strength_label = QLabel("")
        self.strength_label.setFont(QFont("Helvetica", 9))
        form_layout.addWidget(self.strength_label)

        layout.addLayout(form_layout)

        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setMinimumHeight(20)
        layout.addWidget(self.progress_bar)

        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setVisible(False)
        layout.addWidget(self.status_label)

        button_layout = QHBoxLayout()

        self.change_button = QPushButton("Change Password")
        self.change_button.clicked.connect(self.start_change)
        self.change_button.setMinimumHeight(35)
        button_layout.addWidget(self.change_button)

        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        self.cancel_button.setMinimumHeight(35)
        button_layout.addWidget(self.cancel_button)

        layout.addLayout(button_layout)

        self.setLayout(layout)

        self.new_password.textChanged.connect(self.update_password_strength)
        self.confirm_password.textChanged.connect(self.update_password_strength)

    def update_password_strength(self):
        password = self.new_password.text()
        if not password:
            self.strength_label.setText("")
            return

        score = 0
        feedback = []

        if len(password) >= 12:
            score += 25
        else:
            feedback.append("Too short (min 12)")

        if any(c.isupper() for c in password):
            score += 15
        else:
            feedback.append("Add uppercase")

        if any(c.islower() for c in password):
            score += 15
        else:
            feedback.append("Add lowercase")

        if any(c.isdigit() for c in password):
            score += 15
        else:
            feedback.append("Add digits")

        if any(c in "!@#$%^&*()" for c in password):
            score += 20
        else:
            feedback.append("Add special chars")

        if len(set(password)) > len(password) * 0.7:
            score += 10

        if score >= 80:
            strength = "Strong"
            color = "green"
        elif score >= 50:
            strength = "Medium"
            color = "orange"
        else:
            strength = "Weak"
            color = "red"

        feedback_text = ", ".join(feedback) if feedback else "Good password!"
        self.strength_label.setText(f"Strength: {strength} ({score}/100) - {feedback_text}")
        self.strength_label.setStyleSheet(f"color: {color};")

    def validate_inputs(self):
        if not self.current_password.text():
            QMessageBox.warning(self, "Validation Error", "Current password is required")
            return False

        new_pass = self.new_password.text()
        if not new_pass:
            QMessageBox.warning(self, "Validation Error", "New password is required")
            return False

        if new_pass != self.confirm_password.text():
            QMessageBox.warning(self, "Validation Error", "New passwords do not match")
            return False

        if len(new_pass) < 12:
            reply = QMessageBox.question(
                self, "Weak Password",
                "Password is less than 12 characters. Continue anyway?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.No:
                return False

        return True

    def start_change(self):
        if not self.validate_inputs():
            return

        self.change_button.setEnabled(False)
        self.cancel_button.setText("Cancel")
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.status_label.setVisible(True)
        self.status_label.setText("Starting password change...")

        self.worker = ChangePasswordWorker(
            self.key_manager,
            self.current_password.text(),
            self.new_password.text(),
            self.db_path,
            self.crypto_service
        )

        self.worker.progress.connect(self.update_progress)
        self.worker.status.connect(self.update_status)
        self.worker.finished.connect(self.change_finished)
        self.worker.start()

    def update_progress(self, value):
        self.progress_bar.setValue(value)

    def update_status(self, message):
        self.status_label.setText(message)

    def change_finished(self, success, message):
        self.progress_bar.setVisible(False)
        self.status_label.setVisible(False)

        if success:
            QMessageBox.information(self, "Success", message)
            self.accept()
        else:
            QMessageBox.critical(self, "Error", message)
            self.change_button.setEnabled(True)
            self.cancel_button.setText("Cancel")

    def reject(self):
        if self.worker and self.worker.isRunning():
            self.worker.terminate()
            self.worker.wait()
        super().reject()