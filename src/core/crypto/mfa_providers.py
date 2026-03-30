import secrets
import hashlib
import hmac
import base64
import time
from abc import ABC, abstractmethod
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass
from enum import Enum
import json


class MFAType(Enum):
    TOTP = "totp"
    HOTP = "hotp"
    SMS = "sms"
    EMAIL = "email"
    BACKUP_CODE = "backup_code"
    SECURITY_KEY = "security_key"


class MFAStatus(Enum):
    DISABLED = "disabled"
    ENABLED = "enabled"
    PENDING_VERIFICATION = "pending_verification"
    LOCKED = "locked"


@dataclass
class MFAConfig:
    mfa_type: MFAType
    enabled: bool
    secret: Optional[str] = None
    backup_codes: Optional[List[str]] = None
    phone_number: Optional[str] = None
    email: Optional[str] = None
    counter: int = 0
    lockout_until: Optional[float] = None
    failed_attempts: int = 0
    max_attempts: int = 5
    lockout_duration: int = 300


class MFAProvider(ABC):
    def __init__(self, config: MFAConfig):
        self.config = config
        self._failed_attempts = 0
        self._last_attempt_time = 0

    @abstractmethod
    def generate_secret(self) -> str:
        pass

    @abstractmethod
    def verify_code(self, code: str) -> bool:
        pass

    @abstractmethod
    def get_setup_data(self) -> Dict:
        pass

    def check_lockout(self) -> bool:
        if self.config.lockout_until and time.time() < self.config.lockout_until:
            return True

        if self.config.lockout_until and time.time() >= self.config.lockout_until:
            self.config.failed_attempts = 0
            self.config.lockout_until = None

        return False

    def record_failed_attempt(self):
        self.config.failed_attempts += 1
        if self.config.failed_attempts >= self.config.max_attempts:
            self.config.lockout_until = time.time() + self.config.lockout_duration

    def record_successful_attempt(self):
        self.config.failed_attempts = 0
        self.config.lockout_until = None


class TOTPProvider(MFAProvider):
    def __init__(self, config: MFAConfig):
        super().__init__(config)
        self.time_step = 30
        self.digits = 6

    def generate_secret(self) -> str:
        secret = secrets.token_bytes(20)
        self.config.secret = base64.b32encode(secret).decode('utf-8')
        return self.config.secret

    def _get_totp_token(self, secret: str, timestamp: int = None) -> str:
        if timestamp is None:
            timestamp = int(time.time() / self.time_step)

        secret_bytes = base64.b32decode(secret.upper())
        counter_bytes = timestamp.to_bytes(8, 'big')

        hmac_hash = hmac.new(secret_bytes, counter_bytes, hashlib.sha1).digest()
        offset = hmac_hash[-1] & 0x0f
        code = ((hmac_hash[offset] & 0x7f) << 24 |
                (hmac_hash[offset + 1] & 0xff) << 16 |
                (hmac_hash[offset + 2] & 0xff) << 8 |
                (hmac_hash[offset + 3] & 0xff))

        code = code % (10 ** self.digits)
        return str(code).zfill(self.digits)

    def verify_code(self, code: str) -> bool:
        if self.check_lockout():
            return False

        if not self.config.secret:
            return False

        current_time = int(time.time() / self.time_step)

        for i in range(-1, 2):
            expected = self._get_totp_token(self.config.secret, current_time + i)
            if hmac.compare_digest(code, expected):
                self.record_successful_attempt()
                return True

        self.record_failed_attempt()
        return False

    def get_setup_data(self) -> Dict:
        if not self.config.secret:
            self.generate_secret()

        issuer = "CryptoSafe"
        account = "user"

        otp_auth_url = f"otpauth://totp/{issuer}:{account}?secret={self.config.secret}&issuer={issuer}"

        return {
            'secret': self.config.secret,
            'otp_auth_url': otp_auth_url,
            'qr_code_data': otp_auth_url,
            'type': 'totp'
        }


class HOTPProvider(MFAProvider):
    def __init__(self, config: MFAConfig):
        super().__init__(config)
        self.digits = 6

    def generate_secret(self) -> str:
        secret = secrets.token_bytes(20)
        self.config.secret = base64.b32encode(secret).decode('utf-8')
        return self.config.secret

    def _get_hotp_token(self, secret: str, counter: int) -> str:
        secret_bytes = base64.b32decode(secret.upper())
        counter_bytes = counter.to_bytes(8, 'big')

        hmac_hash = hmac.new(secret_bytes, counter_bytes, hashlib.sha1).digest()
        offset = hmac_hash[-1] & 0x0f
        code = ((hmac_hash[offset] & 0x7f) << 24 |
                (hmac_hash[offset + 1] & 0xff) << 16 |
                (hmac_hash[offset + 2] & 0xff) << 8 |
                (hmac_hash[offset + 3] & 0xff))

        code = code % (10 ** self.digits)
        return str(code).zfill(self.digits)

    def verify_code(self, code: str) -> bool:
        if self.check_lockout():
            return False

        if not self.config.secret:
            return False

        expected = self._get_hotp_token(self.config.secret, self.config.counter)

        if hmac.compare_digest(code, expected):
            self.config.counter += 1
            self.record_successful_attempt()
            return True

        self.record_failed_attempt()
        return False

    def get_setup_data(self) -> Dict:
        if not self.config.secret:
            self.generate_secret()

        return {
            'secret': self.config.secret,
            'counter': self.config.counter,
            'type': 'hotp'
        }


class BackupCodeProvider(MFAProvider):
    def __init__(self, config: MFAConfig):
        super().__init__(config)
        self.code_count = 10
        self.code_length = 8

    def generate_secret(self) -> str:
        codes = []
        for i in range(self.code_count):
            code = secrets.token_hex(self.code_length // 2).upper()
            codes.append(code)

        self.config.backup_codes = codes
        return json.dumps(codes)

    def verify_code(self, code: str) -> bool:
        if self.check_lockout():
            return False

        if not self.config.backup_codes:
            return False

        code_upper = code.upper().strip()

        for i, backup_code in enumerate(self.config.backup_codes):
            if hmac.compare_digest(code_upper, backup_code):
                self.config.backup_codes.pop(i)
                self.record_successful_attempt()
                return True

        self.record_failed_attempt()
        return False

    def get_setup_data(self) -> Dict:
        if not self.config.backup_codes:
            self.generate_secret()

        return {
            'backup_codes': self.config.backup_codes,
            'instructions': 'Store these codes in a safe place. Each code can be used only once.',
            'type': 'backup_code'
        }


class SMSProvider(MFAProvider):
    def __init__(self, config: MFAConfig, sms_sender=None):
        super().__init__(config)
        self.sms_sender = sms_sender
        self._pending_code = None
        self._pending_expiry = 0
        self.code_length = 6

    def generate_secret(self) -> str:
        if not self.config.phone_number:
            raise ValueError("Phone number not set")
        return self.config.phone_number

    def send_code(self) -> str:
        if not self.config.phone_number:
            raise ValueError("Phone number not set")

        code = ''.join([str(secrets.randbelow(10)) for _ in range(self.code_length)])
        self._pending_code = code
        self._pending_expiry = time.time() + 300

        if self.sms_sender:
            self.sms_sender.send(self.config.phone_number, f"Your CryptoSafe verification code is: {code}")

        return code

    def verify_code(self, code: str) -> bool:
        if self.check_lockout():
            return False

        if not self._pending_code or time.time() > self._pending_expiry:
            return False

        if hmac.compare_digest(code, self._pending_code):
            self._pending_code = None
            self.record_successful_attempt()
            return True

        self.record_failed_attempt()
        return False

    def get_setup_data(self) -> Dict:
        return {
            'phone_number': self.config.phone_number,
            'type': 'sms'
        }


class EmailProvider(MFAProvider):
    def __init__(self, config: MFAConfig, email_sender=None):
        super().__init__(config)
        self.email_sender = email_sender
        self._pending_code = None
        self._pending_expiry = 0
        self.code_length = 6

    def generate_secret(self) -> str:
        if not self.config.email:
            raise ValueError("Email not set")
        return self.config.email

    def send_code(self) -> str:
        if not self.config.email:
            raise ValueError("Email not set")

        code = ''.join([str(secrets.randbelow(10)) for _ in range(self.code_length)])
        self._pending_code = code
        self._pending_expiry = time.time() + 300

        if self.email_sender:
            self.email_sender.send(self.config.email, "CryptoSafe Verification Code",
                                   f"Your verification code is: {code}")

        return code

    def verify_code(self, code: str) -> bool:
        if self.check_lockout():
            return False

        if not self._pending_code or time.time() > self._pending_expiry:
            return False

        if hmac.compare_digest(code, self._pending_code):
            self._pending_code = None
            self.record_successful_attempt()
            return True

        self.record_failed_attempt()
        return False

    def get_setup_data(self) -> Dict:
        return {
            'email': self.config.email,
            'type': 'email'
        }