from argon2 import PasswordHasher, Type
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import secrets
import hashlib
from enum import Enum
from typing import Optional, Dict, Tuple
from src.core.crypto.password_validator import PasswordValidator
from src.core.crypto.parameter_validator import ParameterValidator


class KeyType(Enum):
    ENCRYPTION = "encryption"
    AUTHENTICATION = "authentication"
    AUDIT_SIGNING = "audit_signing"
    SHARING = "sharing"
    TOTP = "totp"
    BACKUP = "backup"
    SESSION = "session"


class KeyPurpose(Enum):
    VAULT_ENCRYPTION = "vault_encryption"
    MASTER_AUTH = "master_auth"
    AUDIT_LOG_SIGNING = "audit_log_signing"
    AUDIT_LOG_VERIFICATION = "audit_log_verification"
    EXPORT_ENCRYPTION = "export_encryption"
    SECURE_SHARING = "secure_sharing"
    TOTP_GENERATION = "totp_generation"
    BACKUP_ENCRYPTION = "backup_encryption"
    SESSION_KEY = "session_key"


class KeyDerivation:
    def __init__(self, config=None):
        config = config or {}

        self.password_validator = PasswordValidator()
        self.parameter_validator = ParameterValidator()

        self.argon2_time = config.get('argon2_time', 3)
        self.argon2_memory = config.get('argon2_memory', 65536)
        self.argon2_parallelism = config.get('argon2_parallelism', 4)
        self.pbkdf2_iterations = config.get('pbkdf2_iterations', 600000)

        is_valid, errors = self.parameter_validator.validate_combined_params(
            self.argon2_time, self.argon2_memory, self.argon2_parallelism, self.pbkdf2_iterations
        )

        if not is_valid:
            safe_defaults = self.parameter_validator.get_safe_defaults()
            self.argon2_time = safe_defaults['argon2_time']
            self.argon2_memory = safe_defaults['argon2_memory']
            self.argon2_parallelism = safe_defaults['argon2_parallelism']
            self.pbkdf2_iterations = safe_defaults['pbkdf2_iterations']

        self.auth_hasher = PasswordHasher(
            time_cost=self.argon2_time,
            memory_cost=self.argon2_memory,
            parallelism=self.argon2_parallelism,
            hash_len=32,
            salt_len=16,
            type=Type.ID
        )

        self._key_derivations = {
            KeyType.ENCRYPTION: self._derive_encryption_key,
            KeyType.AUTHENTICATION: self._derive_authentication_key,
            KeyType.AUDIT_SIGNING: self._derive_audit_signing_key,
            KeyType.SHARING: self._derive_sharing_key,
            KeyType.TOTP: self._derive_totp_key,
            KeyType.BACKUP: self._derive_backup_key,
            KeyType.SESSION: self._derive_session_key
        }

    def update_settings(self, config):
        new_argon2_time = config.get('argon2_time', self.argon2_time)
        new_argon2_memory = config.get('argon2_memory', self.argon2_memory)
        new_argon2_parallelism = config.get('argon2_parallelism', self.argon2_parallelism)
        new_pbkdf2_iterations = config.get('pbkdf2_iterations', self.pbkdf2_iterations)

        is_valid, errors = self.parameter_validator.validate_combined_params(
            new_argon2_time, new_argon2_memory, new_argon2_parallelism, new_pbkdf2_iterations
        )

        if is_valid:
            self.argon2_time = new_argon2_time
            self.argon2_memory = new_argon2_memory
            self.argon2_parallelism = new_argon2_parallelism
            self.pbkdf2_iterations = new_pbkdf2_iterations
        else:
            raise ValueError(f"Invalid parameters: {', '.join(errors)}")

        self.auth_hasher = PasswordHasher(
            time_cost=self.argon2_time,
            memory_cost=self.argon2_memory,
            parallelism=self.argon2_parallelism,
            hash_len=32,
            salt_len=16,
            type=Type.ID
        )

    def update_password_policy(self, min_length=12, require_uppercase=True, require_lowercase=True, require_digits=True,
                               require_symbols=True, check_common=True):
        self.password_validator.min_length = min_length
        self.password_validator.require_uppercase = require_uppercase
        self.password_validator.require_lowercase = require_lowercase
        self.password_validator.require_digits = require_digits
        self.password_validator.require_symbols = require_symbols

    def validate_password_strength(self, password: str) -> tuple:
        return self.password_validator.validate(password)

    def get_password_strength(self, password: str) -> int:
        return self.password_validator.get_strength_score(password)

    def create_auth_hash(self, password: str):
        is_valid, errors = self.validate_password_strength(password)
        if not is_valid:
            raise ValueError(f"Password does not meet requirements: {', '.join(errors)}")

        hash_str = self.auth_hasher.hash(password)
        salt = secrets.token_bytes(16)
        return hash_str, salt

    def verify_password(self, password: str, stored_hash: str) -> bool:
        try:
            return self.auth_hasher.verify(stored_hash, password)
        except Exception:
            secrets.compare_digest(b'dummy', b'dummy')
            return False

    def derive_encryption_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.pbkdf2_iterations,
        )
        return kdf.derive(password.encode('utf-8'))

    def _derive_encryption_key(self, master_key: bytes, salt: bytes, context: bytes = None) -> bytes:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=context or b"encryption_key",
            backend=default_backend()
        )
        return hkdf.derive(master_key)

    def _derive_authentication_key(self, master_key: bytes, salt: bytes, context: bytes = None) -> bytes:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=context or b"authentication_key",
            backend=default_backend()
        )
        return hkdf.derive(master_key)

    def _derive_audit_signing_key(self, master_key: bytes, salt: bytes, context: bytes = None) -> Tuple[bytes, bytes]:
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=context or b"audit_signing_key",
            backend=default_backend()
        )

        key_material = hkdf.derive(master_key)

        signing_key = hashlib.sha256(key_material + private_bytes).digest()
        verification_key = hashlib.sha256(signing_key).digest()

        return signing_key, verification_key

    def _derive_sharing_key(self, master_key: bytes, salt: bytes, context: bytes = None) -> bytes:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=context or b"sharing_key",
            backend=default_backend()
        )
        return hkdf.derive(master_key)

    def _derive_totp_key(self, master_key: bytes, salt: bytes, context: bytes = None) -> bytes:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=20,
            salt=salt,
            info=context or b"totp_key",
            backend=default_backend()
        )
        return hkdf.derive(master_key)

    def _derive_backup_key(self, master_key: bytes, salt: bytes, context: bytes = None) -> bytes:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=context or b"backup_key",
            backend=default_backend()
        )
        return hkdf.derive(master_key)

    def _derive_session_key(self, master_key: bytes, salt: bytes, context: bytes = None) -> bytes:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=context or b"session_key",
            backend=default_backend()
        )
        return hkdf.derive(master_key)

    def derive_key_for_purpose(self, master_key: bytes, purpose: KeyPurpose, salt: bytes,
                               context: bytes = None) -> bytes:
        purpose_map = {
            KeyPurpose.VAULT_ENCRYPTION: (KeyType.ENCRYPTION, b"vault_encryption"),
            KeyPurpose.MASTER_AUTH: (KeyType.AUTHENTICATION, b"master_auth"),
            KeyPurpose.AUDIT_LOG_SIGNING: (KeyType.AUDIT_SIGNING, b"audit_signing"),
            KeyPurpose.AUDIT_LOG_VERIFICATION: (KeyType.AUDIT_SIGNING, b"audit_verification"),
            KeyPurpose.EXPORT_ENCRYPTION: (KeyType.SHARING, b"export_encryption"),
            KeyPurpose.SECURE_SHARING: (KeyType.SHARING, b"secure_sharing"),
            KeyPurpose.TOTP_GENERATION: (KeyType.TOTP, b"totp_generation"),
            KeyPurpose.BACKUP_ENCRYPTION: (KeyType.BACKUP, b"backup_encryption"),
            KeyPurpose.SESSION_KEY: (KeyType.SESSION, b"session_key")
        }

        if purpose not in purpose_map:
            raise ValueError(f"Unknown key purpose: {purpose}")

        key_type, default_context = purpose_map[purpose]
        final_context = context if context else default_context

        derivation_func = self._key_derivations.get(key_type)
        if not derivation_func:
            raise ValueError(f"No derivation function for key type: {key_type}")

        result = derivation_func(master_key, salt, final_context)

        if key_type == KeyType.AUDIT_SIGNING:
            return result[0]

        return result

    def derive_key_with_label(self, master_key: bytes, label: str, salt: bytes) -> bytes:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=label.encode('utf-8'),
            backend=default_backend()
        )
        return hkdf.derive(master_key)

    def derive_multiple_keys(self, master_key: bytes, salt: bytes, purposes: list) -> Dict[str, bytes]:
        keys = {}

        for purpose in purposes:
            if isinstance(purpose, KeyPurpose):
                key = self.derive_key_for_purpose(master_key, purpose, salt)
                keys[purpose.value] = key
            elif isinstance(purpose, str):
                key = self.derive_key_with_label(master_key, purpose, salt)
                keys[purpose] = key

        return keys

    def get_key_info(self, key_type: KeyType) -> Dict:
        info = {
            KeyType.ENCRYPTION: {
                'name': 'Encryption Key',
                'length': 32,
                'algorithm': 'AES-256-GCM',
                'purpose': 'Vault entry encryption',
                'derivation': 'HKDF-SHA256'
            },
            KeyType.AUTHENTICATION: {
                'name': 'Authentication Key',
                'length': 32,
                'algorithm': 'HMAC-SHA256',
                'purpose': 'Master password verification',
                'derivation': 'HKDF-SHA256'
            },
            KeyType.AUDIT_SIGNING: {
                'name': 'Audit Signing Key',
                'length': 32,
                'algorithm': 'Ed25519',
                'purpose': 'Audit log signing and verification',
                'derivation': 'HKDF-SHA256 + EC'
            },
            KeyType.SHARING: {
                'name': 'Sharing Key',
                'length': 32,
                'algorithm': 'AES-256-GCM',
                'purpose': 'Secure export and sharing',
                'derivation': 'HKDF-SHA256'
            },
            KeyType.TOTP: {
                'name': 'TOTP Key',
                'length': 20,
                'algorithm': 'HMAC-SHA1',
                'purpose': 'TOTP generation',
                'derivation': 'HKDF-SHA256'
            },
            KeyType.BACKUP: {
                'name': 'Backup Key',
                'length': 32,
                'algorithm': 'AES-256-GCM',
                'purpose': 'Backup encryption',
                'derivation': 'HKDF-SHA256'
            },
            KeyType.SESSION: {
                'name': 'Session Key',
                'length': 32,
                'algorithm': 'AES-256-GCM',
                'purpose': 'Session encryption',
                'derivation': 'HKDF-SHA256'
            }
        }

        return info.get(key_type, {})

    def validate_params(self) -> tuple:
        return self.parameter_validator.validate_combined_params(
            self.argon2_time, self.argon2_memory, self.argon2_parallelism, self.pbkdf2_iterations
        )

    def get_current_params(self) -> dict:
        return {
            'argon2_time': self.argon2_time,
            'argon2_memory': self.argon2_memory,
            'argon2_parallelism': self.argon2_parallelism,
            'pbkdf2_iterations': self.pbkdf2_iterations
        }

    def get_estimated_derivation_time(self) -> int:
        return self.parameter_validator.estimate_derivation_time(
            self.argon2_time, self.argon2_memory, self.argon2_parallelism, self.pbkdf2_iterations
        )