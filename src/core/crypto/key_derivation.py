from argon2 import PasswordHasher, Type
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
import secrets
import json

class KeyDerivation:
    def __init__(self, config=None):
        config = config or {}

        self._validate_argon2_params(config)

        self.auth_hasher = PasswordHasher(
            time_cost=config.get('argon2_time', 3),
            memory_cost=config.get('argon2_memory', 65536),
            parallelism=config.get('argon2_parallelism', 4),
            hash_len=32,
            salt_len=16,
            type=Type.ID
        )

        self.pbkdf2_iterations = config.get('pbkdf2_iterations', 600000)

    def _validate_argon2_params(self, config):
        time_cost = config.get('argon2_time', 3)
        memory_cost = config.get('argon2_memory', 65536)
        parallelism = config.get('argon2_parallelism', 4)

        if time_cost > 10:
            raise ValueError("Time cost too high: maximum 10 iterations")
        if memory_cost > 1024 * 1024:
            raise ValueError("Memory cost too high: maximum 1GB")
        if parallelism > 8:
            raise ValueError("Parallelism too high: maximum 8 lanes")
        if time_cost < 1:
            raise ValueError("Time cost too low: minimum 1 iteration")
        if memory_cost < 8192:
            raise ValueError("Memory cost too low: minimum 8MB")
        if parallelism < 1:
            raise ValueError("Parallelism too low: minimum 1 lane")

    def create_auth_hash(self, password):
        hash_str = self.auth_hasher.hash(password)
        params = {
            'algorithm': 'argon2id',
            'time_cost': 3,
            'memory_cost': 65536,
            'parallelism': 4,
            'hash_len': 32,
            'salt_len': 16,
            'version': 1
        }
        return hash_str, params

    def verify_password(self, password, stored_hash):
        try:
            return self.auth_hasher.verify(stored_hash, password)
        except Exception:
            secrets.compare_digest(b'dummy', b'dummy')
            return False

    def derive_encryption_key(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.pbkdf2_iterations,
        )
        return kdf.derive(password.encode('utf-8'))

    def create_encryption_params(self):
        return {
            'algorithm': 'pbkdf2',
            'iterations': self.pbkdf2_iterations,
            'key_length': 32,
            'hash_function': 'SHA256',
            'version': 1
        }

    def derive_audit_key(self, master_key: bytes, salt: bytes) -> bytes:
        return self._hkdf_expand(master_key, b"audit_signing", 32, salt)

    def derive_sharing_key(self, master_key: bytes, salt: bytes) -> bytes:
        return self._hkdf_expand(master_key, b"sharing_export", 32, salt)

    def derive_totp_key(self, master_key: bytes, salt: bytes) -> bytes:
        return self._hkdf_expand(master_key, b"totp_generation", 20, salt)

    def _hkdf_expand(self, prk: bytes, info: bytes, length: int, salt: bytes) -> bytes:
        hkdf = HKDFExpand(
            algorithm=hashes.SHA256(),
            length=length,
            info=info,
        )
        return hkdf.derive(prk)

    def migrate_key_params(self, old_params, new_params):
        return {
            'old_version': old_params.get('version', 1),
            'new_version': new_params.get('version', 2),
            'migration_needed': old_params.get('version', 1) < new_params.get('version', 2)
        }