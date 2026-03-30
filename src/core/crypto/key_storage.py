import time

import keyring
import json
import os
from pathlib import Path
from typing import Optional, Dict, Any
from cryptography.fernet import Fernet
import secrets
import base64

class KeychainStorage:
    SERVICE_NAME = "CryptoSafe"

    def __init__(self, use_keychain: bool = True):
        self.use_keychain = use_keychain and self._is_keychain_available()
        self.fallback_dir = Path.home() / ".cryptosafe"
        self.fallback_file = self.fallback_dir / "key_storage.json"
        self._fallback_key = self._get_or_create_fallback_key()
        self._ensure_fallback_dir()

    def _is_keychain_available(self) -> bool:
        try:
            keyring.get_password(self.SERVICE_NAME, "test")
            return True
        except:
            return False

    def _ensure_fallback_dir(self):
        self.fallback_dir.mkdir(exist_ok=True, mode=0o700)

    def _get_or_create_fallback_key(self) -> bytes:
        key_file = self.fallback_dir / "fallback.key"
        if key_file.exists():
            return key_file.read_bytes()
        key = Fernet.generate_key()
        key_file.write_bytes(key)
        key_file.chmod(0o600)
        return key

    def store_key(self, key_type: str, key_data: bytes, username: str = "default") -> bool:
        if self.use_keychain:
            try:
                keyring.set_password(
                    self.SERVICE_NAME,
                    f"{username}_{key_type}",
                    key_data.hex()
                )
                return True
            except:
                return self._fallback_store(key_type, key_data, username)
        else:
            return self._fallback_store(key_type, key_data, username)

    def retrieve_key(self, key_type: str, username: str = "default") -> Optional[bytes]:
        if self.use_keychain:
            try:
                data = keyring.get_password(
                    self.SERVICE_NAME,
                    f"{username}_{key_type}"
                )
                return bytes.fromhex(data) if data else None
            except:
                return self._fallback_retrieve(key_type, username)
        else:
            return self._fallback_retrieve(key_type, username)

    def delete_key(self, key_type: str, username: str = "default") -> bool:
        if self.use_keychain:
            try:
                keyring.delete_password(
                    self.SERVICE_NAME,
                    f"{username}_{key_type}"
                )
                return True
            except:
                return self._fallback_delete(key_type, username)
        else:
            return self._fallback_delete(key_type, username)

    def _fallback_store(self, key_type: str, key_data: bytes, username: str) -> bool:
        try:
            fernet = Fernet(self._fallback_key)
            encrypted_key = fernet.encrypt(key_data)
            storage = self._load_fallback_storage()
            storage[f"{username}_{key_type}"] = encrypted_key.hex()
            self._save_fallback_storage(storage)
            return True
        except:
            return False

    def _fallback_retrieve(self, key_type: str, username: str) -> Optional[bytes]:
        try:
            fernet = Fernet(self._fallback_key)
            storage = self._load_fallback_storage()
            encrypted_hex = storage.get(f"{username}_{key_type}")
            if not encrypted_hex:
                return None
            encrypted_data = bytes.fromhex(encrypted_hex)
            return fernet.decrypt(encrypted_data)
        except:
            return None

    def _fallback_delete(self, key_type: str, username: str) -> bool:
        try:
            storage = self._load_fallback_storage()
            key = f"{username}_{key_type}"
            if key in storage:
                del storage[key]
                self._save_fallback_storage(storage)
            return True
        except:
            return False

    def _load_fallback_storage(self) -> Dict[str, str]:
        if not self.fallback_file.exists():
            return {}
        try:
            return json.loads(self.fallback_file.read_text())
        except:
            return {}

    def _save_fallback_storage(self, storage: Dict[str, str]):
        self.fallback_file.write_text(json.dumps(storage))
        self.fallback_file.chmod(0o600)

    def clear_all_keys(self, username: str = "default"):
        if self.use_keychain:
            for key_type in ["encryption_key", "auth_hash"]:
                try:
                    keyring.delete_password(self.SERVICE_NAME, f"{username}_{key_type}")
                except:
                    pass
        self._fallback_clear(username)

    def _fallback_clear(self, username: str):
        try:
            storage = self._load_fallback_storage()
            keys_to_delete = [k for k in storage.keys() if k.startswith(f"{username}_")]
            for key in keys_to_delete:
                del storage[key]
            self._save_fallback_storage(storage)
        except:
            pass

class SecureKeyCache:
    def __init__(self, timeout: int = 3600):
        self.timeout = timeout
        self._cache: Dict[str, tuple] = {}

    def set(self, key: str, value: bytes):
        from .secure_memory import SecureBytes
        secure_value = SecureBytes(value)
        self._cache[key] = (secure_value, time.time())

    def get(self, key: str) -> Optional[bytes]:
        import time
        if key not in self._cache:
            return None

        value, timestamp = self._cache[key]
        if time.time() - timestamp > self.timeout:
            del self._cache[key]
            return None

        return bytes(value)

    def delete(self, key: str):
        if key in self._cache:
            from .secure_memory import secure_zero
            value, _ = self._cache[key]
            secure_zero(value)
            del self._cache[key]

    def clear_all(self):
        from .secure_memory import secure_zero
        for value, _ in self._cache.values():
            secure_zero(value)
        self._cache.clear()