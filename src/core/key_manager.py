from .abstract import KeyManager
from .crypto.key_derivation import KeyDerivation
from .crypto.secure_memory import secure_zero
import time

class MasterKeyManager(KeyManager):
    def __init__(self, config=None):
        self._encryption_key = None
        self._unlocked = False
        self._unlock_time = None
        self._last_activity = None
        self.key_derivation = KeyDerivation(config)

    def get_encryption_key(self):
        if self.is_unlocked():
            self._update_activity()
            return self._encryption_key
        return None

    def is_unlocked(self):
        if not self._unlocked:
            return False

        if time.time() - self._last_activity > 3600:
            self.lock()
            return False

        return True

    def unlock(self, password, auth_hash, pbkdf2_salt):
        if not self.key_derivation.verify_password(password, auth_hash):
            return False

        self._encryption_key = self.key_derivation.derive_encryption_key(
            password, pbkdf2_salt
        )

        self._unlocked = True
        self._unlock_time = time.time()
        self._update_activity()

        return True

    def lock(self):
        if self._encryption_key:
            secure_zero(self._encryption_key)
        self._encryption_key = None
        self._unlocked = False

    def _update_activity(self):
        self._last_activity = time.time()