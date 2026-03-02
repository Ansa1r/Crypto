from PyQt6.QtWidgets import QDialog, QTabWidget, QWidget, QVBoxLayout, QLabel, QSpinBox, QComboBox, QPushButton, QFormLayout

class SettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.setMinimumSize(400, 300)
        tabs = QTabWidget()
        self.security_tab = QWidget()
        self.appearance_tab = QWidget()
        self.advanced_tab = QWidget()
        tabs.addTab(self.security_tab, "Security")
        tabs.addTab(self.appearance_tab, "Appearance")
        tabs.addTab(self.advanced_tab, "Advanced")
        self._setup_security_tab()
        self._setup_appearance_tab()
        self._setup_advanced_tab()
        layout = QVBoxLayout(self)
        layout.addWidget(tabs)
        save_btn = QPushButton("Save")
        save_btn.clicked.connect(self.accept)
        layout.addWidget(save_btn)

    def _setup_security_tab(self):
        layout = QFormLayout(self.security_tab)
        self.clipboard_timeout = QSpinBox()
        self.clipboard_timeout.setRange(5, 60)
        self.clipboard_timeout.setValue(15)
        layout.addRow("Clipboard timeout (sec):", self.clipboard_timeout)
        self.auto_lock = QSpinBox()
        self.auto_lock.setRange(1, 30)
        self.auto_lock.setValue(5)
        layout.addRow("Auto-lock after (min):", self.auto_lock)

    def _setup_appearance_tab(self):
        layout = QFormLayout(self.appearance_tab)
        self.theme = QComboBox()
        self.theme.addItems(["Light", "Dark", "System"])
        layout.addRow("Theme:", self.theme)
        self.language = QComboBox()
        self.language.addItems(["English", "Russian"])
        layout.addRow("Language:", self.language)

    def _setup_advanced_tab(self):
        layout = QVBoxLayout(self.advanced_tab)
        backup_btn = QPushButton("Backup now")
        layout.addWidget(backup_btn)
        export_btn = QPushButton("Export vault...")
        layout.addWidget(export_btn)
        layout.addStretch()