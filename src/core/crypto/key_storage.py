import keyring
import json
import os
from pathlib import Path
from typing import Optional, Dict, Any
from .secure_memory import secure_zero
from datetime import time


class KeychainStorage:
    SERVICE_NAME = "CryptoSafe"

    def __init__(self, use_keychain: bool = True):
        self.use_keychain = use_keychain and self._is_keychain_available()
        self.fallback_dir = Path.home() / ".cryptosafe"
        self.fallback_file = self.fallback_dir / "key_storage.json"
        self._ensure_fallback_dir()

    def _is_keychain_available(self) -> bool:
        try:
            keyring.get_password(self.SERVICE_NAME, "test")
            return True
        except:
            return False

    def _ensure_fallback_dir(self):
        self.fallback_dir.mkdir(exist_ok=True, mode=0o700)

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
            storage = self._load_fallback_storage()
            storage[f"{username}_{key_type}"] = key_data.hex()
            self._save_fallback_storage(storage)
            return True
        except:
            return False

    def _fallback_retrieve(self, key_type: str, username: str) -> Optional[bytes]:
        try:
            storage = self._load_fallback_storage()
            data = storage.get(f"{username}_{key_type}")
            return bytes.fromhex(data) if data else None
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
        self._cache: Dict[str, bytes] = {}
        self._timestamps: Dict[str, float] = {}
        self._timeout = timeout

    def set(self, key_id: str, key_data: bytes):
        from .secure_memory import ProtectedMemory
        with ProtectedMemory(key_data) as protected:
            self._cache[key_id] = bytes(protected)
            self._timestamps[key_id] = time.time()

    def get(self, key_id: str) -> Optional[bytes]:
        if key_id not in self._cache:
            return None

        if time.time() - self._timestamps[key_id] > self._timeout:
            self.delete(key_id)
            return None

        return self._cache[key_id]

    def delete(self, key_id: str):
        if key_id in self._cache:
            from .secure_memory import secure_zero
            secure_zero(self._cache[key_id])
            del self._cache[key_id]
            del self._timestamps[key_id]

    def clear_all(self):
        for key_id in list(self._cache.keys()):
            self.delete(key_id)

    def get_active_keys(self) -> list:
        now = time.time()
        return [
            key_id for key_id, ts in self._timestamps.items()
            if now - ts <= self._timeout
        ]