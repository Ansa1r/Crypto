import time
import secrets
from typing import Optional, Tuple, Dict
from src.core.crypto.key_derivation import KeyDerivation
from src.core.crypto.mfa_manager import MFAManager


class AuthenticationService:
    def __init__(self, key_derivation: KeyDerivation, db_path=None):
        self.key_derivation = key_derivation
        self.db_path = db_path
        self.failed_attempts = 0
        self.last_attempt_time = 0.0
        self.session_start = 0.0
        self.last_activity = 0.0
        self.mfa_manager = MFAManager(db_path)
        self.mfa_verified = False
        self.mfa_required = False
        self._pending_mfa_code = None
        self._pending_mfa_expiry = 0

    def get_backoff_delay(self) -> float:
        if self.failed_attempts <= 2:
            return 1.0
        elif self.failed_attempts <= 4:
            return 5.0
        else:
            return 30.0

    def enable_mfa(self, mfa_type, **kwargs) -> Dict:
        return self.mfa_manager.enable_mfa(mfa_type, **kwargs)

    def complete_mfa_setup(self, code: str) -> bool:
        return self.mfa_manager.complete_setup(code)

    def disable_mfa(self):
        self.mfa_manager.disable_mfa()

    def get_mfa_status(self) -> Dict:
        return self.mfa_manager.get_mfa_status()

    def get_mfa_setup_status(self) -> Dict:
        return self.mfa_manager.get_setup_status()

    def verify_mfa_code(self, code: str) -> Tuple[bool, str]:
        if not self.mfa_required:
            return True, "MFA not required"

        success, message = self.mfa_manager.verify_mfa(code)

        if success:
            self.mfa_verified = True
            self._pending_mfa_code = None
        else:
            self._pending_mfa_code = None

        return success, message

    def verify_master_password(self, password: str, stored_hash: str) -> Tuple[bool, Optional[bytes]]:
        now = time.time()
        if now - self.last_attempt_time < self.get_backoff_delay():
            return False, None

        self.last_attempt_time = now

        if self.key_derivation.verify_password(password, stored_hash):
            self.failed_attempts = 0
            self.session_start = now
            self.last_activity = now
            salt = secrets.token_bytes(16)
            enc_key = self.key_derivation.derive_encryption_key(password, salt)

            mfa_status = self.mfa_manager.get_mfa_status()
            if mfa_status['enabled']:
                self.mfa_required = True
                self.mfa_verified = False
                return True, enc_key
            else:
                self.mfa_required = False
                self.mfa_verified = True
                return True, enc_key
        else:
            self.failed_attempts += 1

            hook_result, hook_message = self.mfa_manager._on_failed_attempt_hook({
                'failed_attempts': self.failed_attempts
            })

            return False, None

    def is_mfa_required(self) -> bool:
        return self.mfa_required and not self.mfa_verified

    def is_mfa_verified(self) -> bool:
        return self.mfa_verified

    def update_activity(self):
        self.last_activity = time.time()

    def is_session_active(self, timeout_seconds: int = 3600) -> bool:
        return (time.time() - self.last_activity) < timeout_seconds

    def logout(self):
        self.session_start = 0.0
        self.last_activity = 0.0
        self.failed_attempts = 0
        self.mfa_required = False
        self.mfa_verified = False
        self._pending_mfa_code = None