from typing import Optional, Dict, List
import secrets
from src.core.crypto.key_derivation import KeyDerivation, KeyPurpose, KeyType
from src.core.crypto.key_storage import KeyStorage


class MultiKeyManager:
    def __init__(self, key_derivation: KeyDerivation, username: str = "default"):
        self.key_derivation = key_derivation
        self.username = username
        self._key_cache = {}
        self._key_storage = KeyStorage(username)

    def derive_and_cache_key(self, master_key: bytes, purpose: KeyPurpose, salt: bytes = None,
                             context: bytes = None) -> bytes:
        cache_key = f"{purpose.value}_{salt.hex() if salt else 'default'}"

        if cache_key in self._key_cache:
            return self._key_cache[cache_key]

        if salt is None:
            salt = secrets.token_bytes(16)

        key = self.key_derivation.derive_key_for_purpose(master_key, purpose, salt, context)

        self._key_cache[cache_key] = key

        return key

    def derive_and_store_key(self, master_key: bytes, purpose: KeyPurpose, use_keychain: bool = True) -> bytes:
        salt = secrets.token_bytes(16)
        key = self.derive_and_cache_key(master_key, purpose, salt)

        self._key_storage.store_key_for_purpose(purpose.value, key, salt, use_keychain)

        return key

    def get_stored_key(self, purpose: KeyPurpose) -> Optional[bytes]:
        return self._key_storage.get_key_for_purpose(purpose.value)

    def clear_key_cache(self):
        for key in self._key_cache.values():
            self._key_storage.secure_memory.wipe(key)
        self._key_cache.clear()

    def get_available_key_types(self) -> List[Dict]:
        available = []

        for key_type in KeyType:
            info = self.key_derivation.get_key_info(key_type)
            info['key_type'] = key_type.value
            info['key_type_enum'] = key_type
            available.append(info)

        return available

    def get_key_purposes(self) -> List[Dict]:
        purposes = []

        for purpose in KeyPurpose:
            purposes.append({
                'name': purpose.value,
                'description': self._get_purpose_description(purpose),
                'key_type': self._get_key_type_for_purpose(purpose).value
            })

        return purposes

    def _get_purpose_description(self, purpose: KeyPurpose) -> str:
        descriptions = {
            KeyPurpose.VAULT_ENCRYPTION: "Encrypts and decrypts vault entries",
            KeyPurpose.MASTER_AUTH: "Verifies master password authenticity",
            KeyPurpose.AUDIT_LOG_SIGNING: "Signs audit log entries for integrity",
            KeyPurpose.AUDIT_LOG_VERIFICATION: "Verifies audit log signatures",
            KeyPurpose.EXPORT_ENCRYPTION: "Encrypts exported vault data",
            KeyPurpose.SECURE_SHARING: "Encrypts shared entries",
            KeyPurpose.TOTP_GENERATION: "Generates TOTP codes for 2FA",
            KeyPurpose.BACKUP_ENCRYPTION: "Encrypts backup files",
            KeyPurpose.SESSION_KEY: "Encrypts session data"
        }
        return descriptions.get(purpose, "Unknown purpose")

    def _get_key_type_for_purpose(self, purpose: KeyPurpose) -> KeyType:
        mapping = {
            KeyPurpose.VAULT_ENCRYPTION: KeyType.ENCRYPTION,
            KeyPurpose.MASTER_AUTH: KeyType.AUTHENTICATION,
            KeyPurpose.AUDIT_LOG_SIGNING: KeyType.AUDIT_SIGNING,
            KeyPurpose.AUDIT_LOG_VERIFICATION: KeyType.AUDIT_SIGNING,
            KeyPurpose.EXPORT_ENCRYPTION: KeyType.SHARING,
            KeyPurpose.SECURE_SHARING: KeyType.SHARING,
            KeyPurpose.TOTP_GENERATION: KeyType.TOTP,
            KeyPurpose.BACKUP_ENCRYPTION: KeyType.BACKUP,
            KeyPurpose.SESSION_KEY: KeyType.SESSION
        }
        return mapping.get(purpose, KeyType.ENCRYPTION)