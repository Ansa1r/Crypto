from PyQt6.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QComboBox, QFormLayout, \
    QMessageBox, QTextEdit, QWidget, QGroupBox
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QPixmap
import qrcode
from io import BytesIO
from PIL import ImageQt
from src.core.crypto.authentication import AuthenticationService
from src.core.crypto.mfa_providers import MFAType


class MFASetupDialog(QDialog):
    def __init__(self, parent=None, auth_service: AuthenticationService = None):
        super().__init__(parent)
        self.auth_service = auth_service
        self.setWindowTitle("Multi-Factor Authentication Setup")
        self.setMinimumSize(500, 600)
        self.setModal(True)

        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)

        self.mfa_type_combo = QComboBox()
        self.mfa_type_combo.addItems(["TOTP (Google Authenticator)", "Backup Codes", "SMS", "Email"])
        self.mfa_type_combo.currentTextChanged.connect(self.on_mfa_type_changed)

        type_layout = QFormLayout()
        type_layout.addRow("MFA Method:", self.mfa_type_combo)
        layout.addLayout(type_layout)

        self.setup_widget = QWidget()
        self.setup_layout = QVBoxLayout(self.setup_widget)
        layout.addWidget(self.setup_widget)

        self.code_input = QLineEdit()
        self.code_input.setPlaceholderText("Enter verification code")
        self.code_input.setMaxLength(8)

        self.verify_btn = QPushButton("Verify and Enable")
        self.verify_btn.clicked.connect(self.verify_setup)

        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self.reject)

        button_layout = QHBoxLayout()
        button_layout.addWidget(self.verify_btn)
        button_layout.addWidget(self.cancel_btn)
        layout.addLayout(button_layout)

        self._current_setup_data = None
        self._current_mfa_type = None

        self.on_mfa_type_changed(self.mfa_type_combo.currentText())

    def on_mfa_type_changed(self, text):
        self.clear_setup_widget()

        if text == "TOTP (Google Authenticator)":
            self._setup_totp()
        elif text == "Backup Codes":
            self._setup_backup_codes()
        elif text == "SMS":
            self._setup_sms()
        elif text == "Email":
            self._setup_email()

    def _setup_totp(self):
        setup_data = self.auth_service.enable_mfa(MFAType.TOTP)
        self._current_setup_data = setup_data
        self._current_mfa_type = MFAType.TOTP

        if 'qr_code_data' in setup_data:
            qr = qrcode.QRCode(box_size=10, border=4)
            qr.add_data(setup_data['qr_code_data'])
            qr.make()

            qr_image = qr.make_image(fill_color="black", back_color="white")
            qr_image_qt = ImageQt.ImageQt(qr_image)
            pixmap = QPixmap.fromImage(qr_image_qt)

            qr_label = QLabel()
            qr_label.setPixmap(pixmap.scaled(200, 200, Qt.AspectRatioMode.KeepAspectRatio))
            self.setup_layout.addWidget(qr_label, alignment=Qt.AlignmentFlag.AlignCenter)

        if 'secret' in setup_data:
            secret_label = QLabel(f"Secret Key: {setup_data['secret']}")
            secret_label.setStyleSheet("font-family: monospace; font-size: 12px;")
            secret_label.setWordWrap(True)
            self.setup_layout.addWidget(secret_label)

        instructions = QLabel(
            "1. Install Google Authenticator or similar app on your phone\n"
            "2. Scan the QR code or enter the secret key manually\n"
            "3. Enter the 6-digit code from the app to verify"
        )
        instructions.setStyleSheet("color: gray; font-size: 10px;")
        instructions.setWordWrap(True)
        self.setup_layout.addWidget(instructions)

        self.code_input.setPlaceholderText("Enter 6-digit code")
        self.setup_layout.addWidget(self.code_input)

    def _setup_backup_codes(self):
        setup_data = self.auth_service.enable_mfa(MFAType.BACKUP_CODE)
        self._current_setup_data = setup_data
        self._current_mfa_type = MFAType.BACKUP_CODE

        codes_text = QTextEdit()
        codes_text.setReadOnly(True)
        codes_text.setPlainText("\n".join(setup_data.get('backup_codes', [])))
        codes_text.setMaximumHeight(200)
        self.setup_layout.addWidget(codes_text)

        instructions = QLabel(
            "Store these backup codes in a safe place.\n"
            "Each code can be used only once.\n"
            "Enter one of the codes below to verify setup."
        )
        instructions.setStyleSheet("color: gray; font-size: 10px;")
        instructions.setWordWrap(True)
        self.setup_layout.addWidget(instructions)

        self.code_input.setPlaceholderText("Enter one backup code")
        self.setup_layout.addWidget(self.code_input)

    def _setup_sms(self):
        phone_input = QLineEdit()
        phone_input.setPlaceholderText("+1234567890")
        self.setup_layout.addWidget(phone_input)

        send_btn = QPushButton("Send Verification Code")

        def send_code():
            phone = phone_input.text().strip()
            if phone:
                setup_data = self.auth_service.enable_mfa(MFAType.SMS, phone_number=phone)
                self._current_setup_data = setup_data
                self._current_mfa_type = MFAType.SMS
                send_btn.setEnabled(False)
                send_btn.setText("Code Sent")
                QMessageBox.information(self, "Code Sent", f"Verification code sent to {phone}")

        send_btn.clicked.connect(send_code)
        self.setup_layout.addWidget(send_btn)

        self.setup_layout.addWidget(self.code_input)

    def _setup_email(self):
        email_input = QLineEdit()
        email_input.setPlaceholderText("email@example.com")
        self.setup_layout.addWidget(email_input)

        send_btn = QPushButton("Send Verification Code")

        def send_code():
            email = email_input.text().strip()
            if email:
                setup_data = self.auth_service.enable_mfa(MFAType.EMAIL, email=email)
                self._current_setup_data = setup_data
                self._current_mfa_type = MFAType.EMAIL
                send_btn.setEnabled(False)
                send_btn.setText("Code Sent")
                QMessageBox.information(self, "Code Sent", f"Verification code sent to {email}")

        send_btn.clicked.connect(send_code)
        self.setup_layout.addWidget(send_btn)

        self.setup_layout.addWidget(self.code_input)

    def clear_setup_widget(self):
        while self.setup_layout.count():
            child = self.setup_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

    def verify_setup(self):
        code = self.code_input.text().strip()

        if not code:
            QMessageBox.warning(self, "Error", "Please enter verification code")
            return

        if self.auth_service.complete_mfa_setup(code):
            QMessageBox.information(self, "Success", "MFA has been enabled successfully")
            self.accept()
        else:
            QMessageBox.critical(self, "Error", "Invalid verification code. Please try again.")