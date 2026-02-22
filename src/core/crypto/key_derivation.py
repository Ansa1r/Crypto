from argon2 import PasswordHasher, Type
import secrets


class KeyDerivation:
    def __init__(self):
        self.hasher = PasswordHasher(
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=32,
            salt_len=16,
            type=Type.ID
        )

    def auth_hash(self, password: str) -> str:

        return self.hasher.hash(password)

    def verify(self, password: str, stored_hash: str) -> bool:

        try:
            return self.hasher.verify(stored_hash, password)
        except Exception:
            secrets.compare_digest(b"dummy", b"dummy")
            return False
