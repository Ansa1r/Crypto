from PyQt6.QtWidgets import QDialog, QVBoxLayout, QFormLayout, QLineEdit, QPushButton, QDialogButtonBox, QLabel, \
    QProgressBar, QMessageBox, QHBoxLayout, QTextEdit, QWidget, QCheckBox
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from pathlib import Path
from src.core.key_manager import KeyManager
from src.core.crypto.key_derivation import KeyDerivation
from src.gui.password_strength_indicator import PasswordStrengthIndicator


class ChangePasswordWorker(QThread):
    progress = pyqtSignal(int, int, str, int, int)
    finished = pyqtSignal(bool, str)
    pause_requested = pyqtSignal()

    def __init__(self, key_manager, current_password, new_password, stored_auth_hash, db_path):
        super().__init__()
        self.key_manager = key_manager
        self.current_password = current_password
        self.new_password = new_password
        self.stored_auth_hash = stored_auth_hash
        self.db_path = db_path
        self._paused = False
        self._should_pause = False
        self._should_resume = False
        self._should_stop = False

    def pause(self):
        self._should_pause = True

    def resume(self):
        self._should_resume = True

    def stop(self):
        self._should_stop = True

    def check_pause(self):
        if self._should_pause:
            self._paused = True
            self._should_pause = False
            self.pause_requested.emit()

            while self._paused:
                if self._should_resume:
                    self._paused = False
                    self._should_resume = False
                if self._should_stop:
                    break
                self.msleep(100)

    def run(self):
        def progress_callback(current, total, message, processed, failed):
            self.progress.emit(current, total, message, processed, failed)

        def pause_check_callback():
            self.check_pause()

        success, message = self.key_manager.change_password(
            self.current_password,
            self.new_password,
            self.stored_auth_hash,
            self.db_path,
            progress_callback=progress_callback,
            pause_check_callback=pause_check_callback
        )
        self.finished.emit(success, message)


class ChangePasswordDialog(QDialog):
    def __init__(self, parent=None, key_manager: KeyManager = None, db_path: Path = None, stored_auth_hash: str = None):
        super().__init__(parent)
        self.key_manager = key_manager
        self.db_path = db_path
        self.stored_auth_hash = stored_auth_hash
        self.key_derivation = KeyDerivation()
        self.worker = None
        self.is_paused = False
        self.rollback_performed = False

        self.setWindowTitle("Change Master Password")
        self.setMinimumWidth(550)
        self.setModal(True)

        self._setup_ui()

    def _setup_ui(self):
        self.main_layout = QVBoxLayout(self)

        self.form_widget = QWidget()
        self.form_layout = QFormLayout(self.form_widget)

        self.current_password_edit = QLineEdit()
        self.current_password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.current_password_edit.setPlaceholderText("Enter current master password")
        self.form_layout.addRow("Current Password:", self.current_password_edit)

        self.new_password_edit = QLineEdit()
        self.new_password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.new_password_edit.setPlaceholderText("Enter new master password")
        self.new_password_edit.textChanged.connect(self.on_new_password_changed)

        new_password_layout = QVBoxLayout()
        new_password_layout.addWidget(self.new_password_edit)

        self.strength_indicator = PasswordStrengthIndicator()
        new_password_layout.addWidget(self.strength_indicator)

        self.strength_label = QLabel()
        self.strength_label.setStyleSheet("font-size: 10px;")
        new_password_layout.addWidget(self.strength_label)

        self.password_error_label = QLabel()
        self.password_error_label.setStyleSheet("color: red; font-size: 10px;")
        self.password_error_label.setWordWrap(True)
        new_password_layout.addWidget(self.password_error_label)

        self.form_layout.addRow("New Password:", new_password_layout)

        self.confirm_password_edit = QLineEdit()
        self.confirm_password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_password_edit.setPlaceholderText("Confirm new master password")
        self.confirm_password_edit.textChanged.connect(self.on_confirm_password_changed)

        self.confirm_error_label = QLabel()
        self.confirm_error_label.setStyleSheet("color: red; font-size: 10px;")

        confirm_layout = QVBoxLayout()
        confirm_layout.addWidget(self.confirm_password_edit)
        confirm_layout.addWidget(self.confirm_error_label)

        self.form_layout.addRow("Confirm Password:", confirm_layout)

        self.main_layout.addWidget(self.form_widget)

        self.progress_widget = QWidget()
        self.progress_layout = QVBoxLayout(self.progress_widget)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_layout.addWidget(self.progress_bar)

        self.progress_label = QLabel()
        self.progress_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.progress_layout.addWidget(self.progress_label)

        self.stats_label = QLabel()
        self.stats_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.stats_label.setStyleSheet("font-size: 10px; color: gray;")
        self.progress_layout.addWidget(self.stats_label)

        self.current_entry_label = QLabel()
        self.current_entry_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.current_entry_label.setStyleSheet("font-size: 10px; color: blue;")
        self.current_entry_label.setWordWrap(True)
        self.progress_layout.addWidget(self.current_entry_label)

        self.control_layout = QHBoxLayout()

        self.pause_resume_btn = QPushButton("Pause")
        self.pause_resume_btn.clicked.connect(self.toggle_pause)
        self.control_layout.addWidget(self.pause_resume_btn)

        self.stop_btn = QPushButton("Stop")
        self.stop_btn.clicked.connect(self.stop_reencryption)
        self.control_layout.addWidget(self.stop_btn)

        self.rollback_btn = QPushButton("Rollback")
        self.rollback_btn.clicked.connect(self.rollback)
        self.rollback_btn.setEnabled(False)
        self.rollback_btn.setStyleSheet("background-color: #ff4444; color: white;")
        self.control_layout.addWidget(self.rollback_btn)

        self.progress_layout.addLayout(self.control_layout)

        self.warning_label = QLabel()
        self.warning_label.setStyleSheet("color: orange; font-size: 10px;")
        self.warning_label.setWordWrap(True)
        self.warning_label.setVisible(False)
        self.progress_layout.addWidget(self.warning_label)

        self.failed_entries_widget = QWidget()
        self.failed_entries_layout = QVBoxLayout(self.failed_entries_widget)

        self.failed_entries_label = QLabel("Failed Entries:")
        self.failed_entries_label.setStyleSheet("font-weight: bold;")
        self.failed_entries_layout.addWidget(self.failed_entries_label)

        self.failed_entries_text = QTextEdit()
        self.failed_entries_text.setReadOnly(True)
        self.failed_entries_text.setMaximumHeight(150)
        self.failed_entries_text.setVisible(False)
        self.failed_entries_layout.addWidget(self.failed_entries_text)

        self.progress_layout.addWidget(self.failed_entries_widget)

        self.progress_widget.setVisible(False)
        self.main_layout.addWidget(self.progress_widget)

        self.button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self.ok_button = self.button_box.button(QDialogButtonBox.StandardButton.Ok)
        self.ok_button.setText("Change Password")
        self.ok_button.clicked.connect(self.start_password_change)
        self.button_box.rejected.connect(self.reject)
        self.main_layout.addWidget(self.button_box)

        self.status_timer = QTimer()
        self.status_timer.timeout.connect(self.update_status)

    def on_new_password_changed(self, text):
        if not text:
            self.strength_indicator.set_strength(0)
            self.strength_label.setText("")
            self.password_error_label.setText("")
            return

        is_valid, errors = self.key_derivation.validate_password_strength(text)
        score = self.key_derivation.get_password_strength(text)
        strength_label = self.key_derivation.password_validator.get_strength_label(score)

        self.strength_indicator.set_strength(score)
        self.strength_label.setText(f"Strength: {strength_label}")

        if is_valid:
            self.password_error_label.setText("")
        else:
            self.password_error_label.setText("• " + "\n• ".join(errors))

        self.validate_form()

    def on_confirm_password_changed(self, text):
        self.validate_form()

    def validate_form(self):
        new_password = self.new_password_edit.text()
        confirm_password = self.confirm_password_edit.text()

        if new_password and confirm_password:
            if new_password != confirm_password:
                self.confirm_error_label.setText("Passwords do not match")
                self.ok_button.setEnabled(False)
                return
            else:
                self.confirm_error_label.setText("")

        if not new_password or not confirm_password:
            self.ok_button.setEnabled(False)
            return

        is_valid, errors = self.key_derivation.validate_password_strength(new_password)
        if not is_valid:
            self.ok_button.setEnabled(False)
            return

        if new_password != confirm_password:
            self.ok_button.setEnabled(False)
            return

        self.ok_button.setEnabled(True)

    def start_password_change(self):
        current_password = self.current_password_edit.text()
        new_password = self.new_password_edit.text()
        confirm_password = self.confirm_password_edit.text()

        if not current_password:
            QMessageBox.warning(self, "Error", "Please enter current password")
            return

        if not new_password:
            QMessageBox.warning(self, "Error", "Please enter new password")
            return

        if new_password != confirm_password:
            QMessageBox.warning(self, "Error", "New passwords do not match")
            return

        is_valid, errors = self.key_derivation.validate_password_strength(new_password)
        if not is_valid:
            QMessageBox.warning(self, "Weak Password",
                                "Your new password does not meet security requirements:\n\n" +
                                "\n".join(errors))
            return

        reply = QMessageBox.question(
            self, "Confirm Password Change",
            f"Warning: Changing master password will re-encrypt all {self._get_entry_count()} entries.\n"
            "This process may take a few minutes.\n\n"
            "A backup will be created before starting. If anything goes wrong,\n"
            "you can rollback to the previous state.\n\n"
            "You can pause, resume, or stop the process at any time.\n\n"
            "Do you want to continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            self.start_reencryption(current_password, new_password)

    def _get_entry_count(self):
        try:
            from src.database.db import get_all_vault_entries
            entries = get_all_vault_entries(self.db_path)
            return len(entries)
        except:
            return 0

    def start_reencryption(self, current_password, new_password):
        self.form_widget.setVisible(False)
        self.button_box.setVisible(False)
        self.progress_widget.setVisible(True)
        self.pause_resume_btn.setText("Pause")
        self.pause_resume_btn.setEnabled(True)
        self.stop_btn.setEnabled(True)
        self.rollback_btn.setEnabled(False)
        self.is_paused = False
        self.rollback_performed = False
        self.warning_label.setVisible(False)
        self.failed_entries_text.setVisible(False)
        self.failed_entries_text.clear()

        self.worker = ChangePasswordWorker(
            self.key_manager,
            current_password,
            new_password,
            self.stored_auth_hash,
            self.db_path
        )
        self.worker.progress.connect(self.on_progress)
        self.worker.finished.connect(self.on_finished)
        self.worker.pause_requested.connect(self.on_pause_requested)
        self.worker.start()

        self.status_timer.start(100)

    def toggle_pause(self):
        if self.is_paused:
            self.worker.resume()
            self.pause_resume_btn.setText("Pause")
            self.is_paused = False
        else:
            self.worker.pause()
            self.pause_resume_btn.setText("Resume")
            self.is_paused = True

    def stop_reencryption(self):
        state = self.key_manager.get_reencryption_state()

        reply = QMessageBox.question(
            self, "Stop Re-encryption",
            f"Are you sure you want to stop the re-encryption process?\n\n"
            f"Processed: {state.get('processed_count', 0)} / {state.get('total_entries', 0)} entries\n\n"
            f"WARNING: If you stop now, your vault will be in an inconsistent state.\n"
            f"Some entries will be encrypted with the new key, others with the old key.\n\n"
            f"You can use the Rollback button to restore from the backup.\n\n"
            f"Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            self.worker.stop()
            self.pause_resume_btn.setEnabled(False)
            self.stop_btn.setEnabled(False)
            self.rollback_btn.setEnabled(True)
            self.warning_label.setText("⚠️ Process stopped. Use Rollback to restore from backup.")
            self.warning_label.setVisible(True)
            self.progress_label.setText("Stopped. Rollback available.")

    def rollback(self):
        reply = QMessageBox.question(
            self, "Rollback Password Change",
            "Are you sure you want to rollback the password change?\n\n"
            "This will restore your vault to the state before the password change.\n"
            "All changes made during this process will be lost.\n\n"
            "This action cannot be undone.\n\n"
            "Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            self.rollback_btn.setEnabled(False)
            self.rollback_btn.setText("Rolling back...")

            success, message = self.key_manager.rollback_reencryption(self.db_path)

            if success:
                self.rollback_performed = True
                QMessageBox.information(self, "Rollback Successful",
                                        "Your vault has been restored to its previous state.\n\n"
                                        "You can now close this dialog and try again.")
                self.accept()
            else:
                QMessageBox.critical(self, "Rollback Failed", message)
                self.rollback_btn.setText("Rollback")
                self.rollback_btn.setEnabled(True)

    def on_pause_requested(self):
        self.progress_label.setText("Paused. Click Resume to continue...")
        self.warning_label.setVisible(False)

    def on_progress(self, current, total, message, processed, failed):
        if total > 0:
            percent = int((current / total) * 100)
            self.progress_bar.setValue(percent)

        self.progress_label.setText(f"{message} ({current}/{total})")
        self.stats_label.setText(f"Processed: {processed} | Failed: {failed}")

        if total > 0 and current <= total:
            state = self.key_manager.get_reencryption_state()
            if state.get('current_entry_title'):
                self.current_entry_label.setText(f"Current: {state['current_entry_title']}")

        if failed > 0:
            self.failed_entries_text.setVisible(True)
            state = self.key_manager.get_reencryption_state()
            failed_entries = state.get('failed_entries', [])
            if failed_entries:
                text = ""
                for entry in failed_entries[-10:]:
                    text += f"• {entry['title']}: {entry.get('error', 'Unknown error')}\n"
                self.failed_entries_text.setText(text)

        state = self.key_manager.get_reencryption_state()
        if state.get('backup_exists'):
            self.rollback_btn.setEnabled(True)

    def update_status(self):
        if self.worker and self.worker.isRunning():
            state = self.key_manager.get_reencryption_state()
            if not self.is_paused and state.get('is_paused'):
                self.is_paused = True
                self.pause_resume_btn.setText("Resume")
            elif self.is_paused and not state.get('is_paused'):
                self.is_paused = False
                self.pause_resume_btn.setText("Pause")

    def on_finished(self, success, message):
        self.status_timer.stop()

        if success:
            if "failed" in message.lower():
                QMessageBox.warning(self, "Completed with Warnings", message)
            else:
                QMessageBox.information(self, "Success", message)
            self.accept()
        else:
            state = self.key_manager.get_reencryption_state()
            has_backup = state.get('backup_exists', False)

            if has_backup:
                reply = QMessageBox.critical(
                    self, "Error",
                    f"{message}\n\nA backup exists. Do you want to rollback now?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No | QMessageBox.StandardButton.Cancel
                )

                if reply == QMessageBox.StandardButton.Yes:
                    success, rollback_msg = self.key_manager.rollback_reencryption(self.db_path)
                    if success:
                        QMessageBox.information(self, "Rollback Successful",
                                                "Your vault has been restored to its previous state.")
                        self.accept()
                    else:
                        QMessageBox.critical(self, "Rollback Failed", rollback_msg)
                        self.form_widget.setVisible(True)
                        self.button_box.setVisible(True)
                        self.progress_widget.setVisible(False)
                elif reply == QMessageBox.StandardButton.No:
                    self.form_widget.setVisible(True)
                    self.button_box.setVisible(True)
                    self.progress_widget.setVisible(False)
                else:
                    self.form_widget.setVisible(True)
                    self.button_box.setVisible(True)
                    self.progress_widget.setVisible(False)
            else:
                QMessageBox.critical(self, "Error", message)
                self.form_widget.setVisible(True)
                self.button_box.setVisible(True)
                self.progress_widget.setVisible(False)

            self.current_password_edit.clear()
            self.new_password_edit.clear()
            self.confirm_password_edit.clear()

    def closeEvent(self, event):
        if self.worker and self.worker.isRunning():
            reply = QMessageBox.question(
                self, "Process Running",
                "The password change process is still running.\n"
                "Do you want to stop it and close?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.Yes:
                self.worker.stop()
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()