from PyQt6.QtWidgets import QDialog, QTabWidget, QWidget, QVBoxLayout, QLabel, QSpinBox, QComboBox, QPushButton, \
    QFormLayout, QCheckBox, QGroupBox, QMessageBox, QHBoxLayout
from PyQt6.QtCore import Qt
from src.core.key_manager import KeyManager
from src.database.db import get_all_settings, update_settings, reset_settings_to_default
from src.core.crypto.parameter_validator import ParameterValidator


class SettingsDialog(QDialog):
    def __init__(self, parent=None, key_manager: KeyManager = None, db_path=None):
        super().__init__(parent)
        self.key_manager = key_manager
        self.db_path = db_path
        self.settings = get_all_settings(db_path) if db_path else {}
        self.validator = ParameterValidator()

        self.setWindowTitle("Settings")
        self.setMinimumSize(550, 650)

        tabs = QTabWidget()
        self.password_tab = QWidget()
        self.security_tab = QWidget()
        self.key_derivation_tab = QWidget()
        self.appearance_tab = QWidget()
        self.keychain_tab = QWidget()
        self.backup_tab = QWidget()

        tabs.addTab(self.password_tab, "Password Policy")
        tabs.addTab(self.security_tab, "Security")
        tabs.addTab(self.key_derivation_tab, "Key Derivation")
        tabs.addTab(self.appearance_tab, "Appearance")
        tabs.addTab(self.keychain_tab, "Keychain")
        tabs.addTab(self.backup_tab, "Backup")

        self._setup_password_tab()
        self._setup_security_tab()
        self._setup_key_derivation_tab()
        self._setup_appearance_tab()
        self._setup_keychain_tab()
        self._setup_backup_tab()

        layout = QVBoxLayout(self)
        layout.addWidget(tabs)

        button_layout = QHBoxLayout()

        reset_btn = QPushButton("Reset to Defaults")
        reset_btn.clicked.connect(self.reset_settings)
        button_layout.addWidget(reset_btn)

        button_layout.addStretch()

        save_btn = QPushButton("Save")
        save_btn.clicked.connect(self.save_settings)
        button_layout.addWidget(save_btn)

        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(cancel_btn)

        layout.addLayout(button_layout)

    def _setup_password_tab(self):
        layout = QFormLayout(self.password_tab)

        self.password_min_length = QSpinBox()
        self.password_min_length.setRange(8, 64)
        self.password_min_length.setValue(self.settings.get('password_min_length', 12))
        layout.addRow("Minimum Password Length:", self.password_min_length)

        self.password_require_uppercase = QCheckBox()
        self.password_require_uppercase.setChecked(self.settings.get('password_require_uppercase', True))
        layout.addRow("Require Uppercase Letters:", self.password_require_uppercase)

        self.password_require_lowercase = QCheckBox()
        self.password_require_lowercase.setChecked(self.settings.get('password_require_lowercase', True))
        layout.addRow("Require Lowercase Letters:", self.password_require_lowercase)

        self.password_require_digits = QCheckBox()
        self.password_require_digits.setChecked(self.settings.get('password_require_digits', True))
        layout.addRow("Require Digits:", self.password_require_digits)

        self.password_require_symbols = QCheckBox()
        self.password_require_symbols.setChecked(self.settings.get('password_require_symbols', True))
        layout.addRow("Require Special Characters:", self.password_require_symbols)

        self.password_check_common = QCheckBox()
        self.password_check_common.setChecked(self.settings.get('password_check_common', True))
        layout.addRow("Check Against Common Passwords:", self.password_check_common)

        info_label = QLabel("Note: These settings apply to the master password only.")
        info_label.setStyleSheet("color: gray; font-size: 10px;")
        layout.addRow(info_label)

    def _setup_security_tab(self):
        layout = QFormLayout(self.security_tab)

        self.auto_lock_timeout = QSpinBox()
        self.auto_lock_timeout.setRange(60, 7200)
        self.auto_lock_timeout.setSuffix(" seconds")
        self.auto_lock_timeout.setValue(self.settings.get('auto_lock_timeout', 3600))
        layout.addRow("Auto-lock Timeout:", self.auto_lock_timeout)

        self.clipboard_timeout = QSpinBox()
        self.clipboard_timeout.setRange(5, 300)
        self.clipboard_timeout.setSuffix(" seconds")
        self.clipboard_timeout.setValue(self.settings.get('clipboard_timeout', 15))
        layout.addRow("Clipboard Clear Timeout:", self.clipboard_timeout)

        self.inactivity_lock = QCheckBox()
        self.inactivity_lock.setChecked(self.settings.get('inactivity_lock', True))
        layout.addRow("Lock on Inactivity:", self.inactivity_lock)

        self.minimize_to_tray = QCheckBox()
        self.minimize_to_tray.setChecked(self.settings.get('minimize_to_tray', False))
        layout.addRow("Minimize to System Tray:", self.minimize_to_tray)

    def _setup_key_derivation_tab(self):
        layout = QFormLayout(self.key_derivation_tab)

        self.argon2_time = QSpinBox()
        self.argon2_time.setRange(1, self.validator.max_argon2_time)
        self.argon2_time.setValue(self.settings.get('argon2_time_cost', 3))
        layout.addRow("Argon2 Time Cost:", self.argon2_time)

        self.argon2_memory = QSpinBox()
        self.argon2_memory.setRange(self.validator.min_argon2_memory, self.validator.max_argon2_memory)
        self.argon2_memory.setSuffix(" KB")
        self.argon2_memory.setValue(self.settings.get('argon2_memory_cost', 65536))
        layout.addRow("Argon2 Memory Cost:", self.argon2_memory)

        self.argon2_parallelism = QSpinBox()
        self.argon2_parallelism.setRange(1, self.validator.max_argon2_parallelism)
        self.argon2_parallelism.setValue(self.settings.get('argon2_parallelism', 4))
        layout.addRow("Argon2 Parallelism:", self.argon2_parallelism)

        self.pbkdf2_iterations = QSpinBox()
        self.pbkdf2_iterations.setRange(self.validator.min_pbkdf2_iterations, self.validator.max_pbkdf2_iterations)
        self.pbkdf2_iterations.setSingleStep(100000)
        self.pbkdf2_iterations.setValue(self.settings.get('pbkdf2_iterations', 600000))
        layout.addRow("PBKDF2 Iterations:", self.pbkdf2_iterations)

        self.estimated_time_label = QLabel()
        self.estimated_time_label.setStyleSheet("color: blue; font-size: 10px;")
        layout.addRow("Estimated Derivation Time:", self.estimated_time_label)

        self.warning_label = QLabel()
        self.warning_label.setStyleSheet("color: orange; font-size: 10px;")
        self.warning_label.setWordWrap(True)
        layout.addRow(self.warning_label)

        self.argon2_time.valueChanged.connect(self.update_estimated_time)
        self.argon2_memory.valueChanged.connect(self.update_estimated_time)
        self.argon2_parallelism.valueChanged.connect(self.update_estimated_time)
        self.pbkdf2_iterations.valueChanged.connect(self.update_estimated_time)

        self.update_estimated_time()

    def update_estimated_time(self):
        time_cost = self.argon2_time.value()
        memory_cost = self.argon2_memory.value()
        parallelism = self.argon2_parallelism.value()
        iterations = self.pbkdf2_iterations.value()

        is_valid, errors = self.validator.validate_combined_params(
            time_cost, memory_cost, parallelism, iterations
        )

        if is_valid:
            estimated_ms = self.validator.estimate_derivation_time(
                time_cost, memory_cost, parallelism, iterations
            )

            if estimated_ms < 1000:
                self.estimated_time_label.setText(f"~{estimated_ms} ms")
            else:
                self.estimated_time_label.setText(f"~{estimated_ms / 1000:.1f} seconds")

            if estimated_ms > self.validator.max_key_derivation_time_ms:
                self.warning_label.setText(
                    f"⚠️ Warning: Estimated time ({estimated_ms} ms) exceeds recommended maximum of {self.validator.max_key_derivation_time_ms} ms")
                self.warning_label.setStyleSheet("color: red; font-size: 10px;")
            else:
                self.warning_label.setText("")
        else:
            self.estimated_time_label.setText("Invalid parameters")
            self.warning_label.setText(f"⚠️ {', '.join(errors)}")
            self.warning_label.setStyleSheet("color: red; font-size: 10px;")

    def _setup_appearance_tab(self):
        layout = QFormLayout(self.appearance_tab)

        self.theme = QComboBox()
        self.theme.addItems(["Light", "Dark", "System"])
        current_theme = self.settings.get('theme', 'system')
        theme_index = ["Light", "Dark", "System"].index(current_theme.capitalize()) if current_theme in ["light",
                                                                                                         "dark",
                                                                                                         "system"] else 2
        self.theme.setCurrentIndex(theme_index)
        layout.addRow("Theme:", self.theme)

        self.language = QComboBox()
        self.language.addItems(["English", "Russian"])
        current_lang = self.settings.get('language', 'en')
        lang_index = 0 if current_lang == 'en' else 1
        self.language.setCurrentIndex(lang_index)
        layout.addRow("Language:", self.language)

    def _setup_keychain_tab(self):
        layout = QVBoxLayout(self.keychain_tab)

        keychain_group = QGroupBox("OS Keychain Integration")
        keychain_layout = QVBoxLayout(keychain_group)

        self.keychain_enabled = QCheckBox("Enable OS Keychain")
        self.keychain_enabled.setChecked(self.settings.get('keychain_enabled', True))

        if self.key_manager:
            available = self.key_manager.is_keychain_available()
            self.keychain_enabled.setEnabled(available)
            if not available:
                keychain_layout.addWidget(QLabel("⚠️ Keychain not available on this system"))

        keychain_layout.addWidget(self.keychain_enabled)

        self.fast_unlock_enabled = QCheckBox("Enable Fast Unlock")
        self.fast_unlock_enabled.setChecked(self.settings.get('fast_unlock_enabled', True))
        keychain_layout.addWidget(self.fast_unlock_enabled)

        self.cache_ttl = QSpinBox()
        self.cache_ttl.setRange(300, 86400)
        self.cache_ttl.setSuffix(" seconds")
        self.cache_ttl.setValue(self.settings.get('cache_ttl', 3600))

        cache_layout = QHBoxLayout()
        cache_layout.addWidget(QLabel("Key Cache TTL:"))
        cache_layout.addWidget(self.cache_ttl)
        cache_layout.addStretch()
        keychain_layout.addLayout(cache_layout)

        keychain_layout.addStretch()
        layout.addWidget(keychain_group)

    def _setup_backup_tab(self):
        layout = QFormLayout(self.backup_tab)

        self.backup_enabled = QCheckBox()
        self.backup_enabled.setChecked(self.settings.get('backup_enabled', True))
        layout.addRow("Enable Automatic Backups:", self.backup_enabled)

        self.backup_interval = QSpinBox()
        self.backup_interval.setRange(3600, 604800)
        self.backup_interval.setSuffix(" seconds")
        self.backup_interval.setValue(self.settings.get('backup_interval', 86400))
        layout.addRow("Backup Interval:", self.backup_interval)

        self.backup_retention_days = QSpinBox()
        self.backup_retention_days.setRange(1, 365)
        self.backup_retention_days.setSuffix(" days")
        self.backup_retention_days.setValue(self.settings.get('backup_retention_days', 30))
        layout.addRow("Backup Retention:", self.backup_retention_days)

        self.audit_log_enabled = QCheckBox()
        self.audit_log_enabled.setChecked(self.settings.get('audit_log_enabled', True))
        layout.addRow("Enable Audit Log:", self.audit_log_enabled)

        self.audit_log_retention_days = QSpinBox()
        self.audit_log_retention_days.setRange(7, 365)
        self.audit_log_retention_days.setSuffix(" days")
        self.audit_log_retention_days.setValue(self.settings.get('audit_log_retention_days', 90))
        layout.addRow("Audit Log Retention:", self.audit_log_retention_days)

    def reset_settings(self):
        reply = QMessageBox.question(
            self, "Reset Settings",
            "Are you sure you want to reset all settings to default values?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes and self.db_path:
            reset_settings_to_default(self.db_path)
            self.settings = get_all_settings(self.db_path)

            self.password_min_length.setValue(self.settings.get('password_min_length', 12))
            self.password_require_uppercase.setChecked(self.settings.get('password_require_uppercase', True))
            self.password_require_lowercase.setChecked(self.settings.get('password_require_lowercase', True))
            self.password_require_digits.setChecked(self.settings.get('password_require_digits', True))
            self.password_require_symbols.setChecked(self.settings.get('password_require_symbols', True))
            self.password_check_common.setChecked(self.settings.get('password_check_common', True))

            self.auto_lock_timeout.setValue(self.settings.get('auto_lock_timeout', 3600))
            self.clipboard_timeout.setValue(self.settings.get('clipboard_timeout', 15))
            self.inactivity_lock.setChecked(self.settings.get('inactivity_lock', True))
            self.minimize_to_tray.setChecked(self.settings.get('minimize_to_tray', False))

            self.argon2_time.setValue(self.settings.get('argon2_time_cost', 3))
            self.argon2_memory.setValue(self.settings.get('argon2_memory_cost', 65536))
            self.argon2_parallelism.setValue(self.settings.get('argon2_parallelism', 4))
            self.pbkdf2_iterations.setValue(self.settings.get('pbkdf2_iterations', 600000))

            self.update_estimated_time()

            theme_val = self.settings.get('theme', 'system')
            theme_index = ["Light", "Dark", "System"].index(theme_val.capitalize()) if theme_val in ["light", "dark",
                                                                                                     "system"] else 2
            self.theme.setCurrentIndex(theme_index)

            self.keychain_enabled.setChecked(self.settings.get('keychain_enabled', True))
            self.fast_unlock_enabled.setChecked(self.settings.get('fast_unlock_enabled', True))
            self.cache_ttl.setValue(self.settings.get('cache_ttl', 3600))

            self.backup_enabled.setChecked(self.settings.get('backup_enabled', True))
            self.backup_interval.setValue(self.settings.get('backup_interval', 86400))
            self.backup_retention_days.setValue(self.settings.get('backup_retention_days', 30))
            self.audit_log_enabled.setChecked(self.settings.get('audit_log_enabled', True))
            self.audit_log_retention_days.setValue(self.settings.get('audit_log_retention_days', 90))

            QMessageBox.information(self, "Settings Reset", "All settings have been reset to default values.")

    def save_settings(self):
        if not self.db_path:
            QMessageBox.warning(self, "Error", "No database connection available")
            return

        is_valid, errors = self.validator.validate_combined_params(
            self.argon2_time.value(),
            self.argon2_memory.value(),
            self.argon2_parallelism.value(),
            self.pbkdf2_iterations.value()
        )

        if not is_valid:
            QMessageBox.critical(
                self, "Invalid Parameters",
                f"Cannot save settings due to invalid parameters:\n\n" + "\n".join(errors)
            )
            return

        settings_to_save = {
            'password_min_length': self.password_min_length.value(),
            'password_require_uppercase': self.password_require_uppercase.isChecked(),
            'password_require_lowercase': self.password_require_lowercase.isChecked(),
            'password_require_digits': self.password_require_digits.isChecked(),
            'password_require_symbols': self.password_require_symbols.isChecked(),
            'password_check_common': self.password_check_common.isChecked(),
            'auto_lock_timeout': self.auto_lock_timeout.value(),
            'clipboard_timeout': self.clipboard_timeout.value(),
            'inactivity_lock': self.inactivity_lock.isChecked(),
            'minimize_to_tray': self.minimize_to_tray.isChecked(),
            'argon2_time_cost': self.argon2_time.value(),
            'argon2_memory_cost': self.argon2_memory.value(),
            'argon2_parallelism': self.argon2_parallelism.value(),
            'pbkdf2_iterations': self.pbkdf2_iterations.value(),
            'theme': self.theme.currentText().lower(),
            'language': 'en' if self.language.currentIndex() == 0 else 'ru',
            'keychain_enabled': self.keychain_enabled.isChecked(),
            'fast_unlock_enabled': self.fast_unlock_enabled.isChecked(),
            'cache_ttl': self.cache_ttl.value(),
            'backup_enabled': self.backup_enabled.isChecked(),
            'backup_interval': self.backup_interval.value(),
            'backup_retention_days': self.backup_retention_days.value(),
            'audit_log_enabled': self.audit_log_enabled.isChecked(),
            'audit_log_retention_days': self.audit_log_retention_days.value()
        }

        try:
            update_settings(settings_to_save, self.db_path)

            if self.key_manager:
                self.key_manager.enable_keychain(self.keychain_enabled.isChecked())
                self.key_manager.enable_fast_unlock(self.fast_unlock_enabled.isChecked())
                self.key_manager.set_cache_options(self.fast_unlock_enabled.isChecked(), self.cache_ttl.value())

            QMessageBox.information(self, "Success", "Settings saved successfully")
            self.accept()
        except ValueError as e:
            QMessageBox.critical(self, "Error", f"Failed to save settings:\n\n{str(e)}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save settings:\n\n{str(e)}")