from PyQt6.QtWidgets import QLineEdit, QPushButton, QHBoxLayout, QWidget
from PyQt6.QtCore import Qt

class PasswordEntry(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.entry = QLineEdit()
        self.entry.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.entry)
        self.toggle_btn = QPushButton("Show")
        self.toggle_btn.setCheckable(True)
        self.toggle_btn.toggled.connect(self.toggle_visibility)
        layout.addWidget(self.toggle_btn)

    def text(self):
        return self.entry.text()

    def setText(self, text):
        self.entry.setText(text)

    def toggle_visibility(self, checked):
        if checked:
            self.entry.setEchoMode(QLineEdit.EchoMode.Normal)
            self.toggle_btn.setText("Hide")
        else:
            self.entry.setEchoMode(QLineEdit.EchoMode.Password)
            self.toggle_btn.setText("Show")