import hashlib
import secrets
from .crypto.secure_memory import secure_wipe_str, secure_zero_bytes

class KeyManager:
    def derive_key(self, password: str, salt: bytes) -> bytes:
        derived = hashlib.sha256(password.encode() + salt).digest()
        secure_wipe_str(password)
        secure_zero_bytes(salt)
        return derived

    def store_key(self):
        pass

    def load_key(self):
        pass

    def generate_salt(self) -> bytes:
        return secrets.token_bytes(16)