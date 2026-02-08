import hashlib
import secrets


class KeyManager:
    """
    Placeholder key manager for Sprint 1.
    """

    def derive_key(self, password: str, salt: bytes) -> bytes:
        return hashlib.sha256(password.encode() + salt).digest()

    def store_key(self):
        # Implemented in Sprint 2
        pass

    def load_key(self):
        # Implemented in Sprint 2
        pass

    def generate_salt(self) -> bytes:
        return secrets.token_bytes(16)
