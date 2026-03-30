import time
import os
import json
from typing import Optional, Dict
from pathlib import Path
from src.core.crypto.secure_memory import SecureMemory
from src.core.crypto.keychain_integration import KeychainIntegration


class KeyStorage:
    def __init__(self, username: str = "default", fallback_dir: Optional[Path] = None, auto_lock_manager=None):
        self.secure_memory = SecureMemory()
        self.encryption_key = None
        self._multi_keys = {}
        self.key_timestamp = 0.0
        self.inactivity_timeout = 3600
        self.username = username
        self.keychain = KeychainIntegration()
        self.use_keychain = self.keychain.is_available()
        self.cache_derived_key = True
        self.cache_ttl = 3600
        self.auto_lock_manager = auto_lock_manager
        self._last_access_time = time.time()

        if fallback_dir is None:
            self.fallback_dir = Path.home() / ".cryptosafe"
        else:
            self.fallback_dir = fallback_dir

        self.fallback_dir.mkdir(parents=True, exist_ok=True)

    def _update_last_access(self):
        self._last_access_time = time.time()
        if self.auto_lock_manager:
            self.auto_lock_manager.on_activity_detected()

    def _is_expired(self) -> bool:
        if self.auto_lock_manager and self.auto_lock_manager.is_locked():
            return True

        if (time.time() - self.key_timestamp) > self.inactivity_timeout:
            return True

        return False

    def enable_keychain(self, enable: bool):
        if enable and self.keychain.is_available():
            self.use_keychain = True
        else:
            self.use_keychain = False

    def is_keychain_available(self) -> bool:
        return self.keychain.is_available()

    def get_keychain_error(self) -> Optional[str]:
        return self.keychain.get_last_error()

    def _get_fallback_path(self, key_type: str) -> Path:
        return self.fallback_dir / f"{self.username}_{key_type}.json"

    def _store_to_fallback(self, key_type: str, data: Dict) -> bool:
        try:
            file_path = self._get_fallback_path(key_type)
            data['stored_at'] = time.time()
            with open(file_path, 'w') as f:
                json.dump(data, f)
            return True
        except Exception:
            return False

    def _load_from_fallback(self, key_type: str) -> Optional[Dict]:
        try:
            file_path = self._get_fallback_path(key_type)
            if file_path.exists():
                with open(file_path, 'r') as f:
                    data = json.load(f)
                return data
            return None
        except Exception:
            return None

    def _delete_fallback(self, key_type: str) -> bool:
        try:
            file_path = self._get_fallback_path(key_type)
            if file_path.exists():
                file_path.unlink()
            return True
        except Exception:
            return False

    def store_encryption_key(self, key: bytes, use_keychain: bool = True, cache_to_keychain: bool = True):
        self.encryption_key = self.secure_memory.protect(key)
        self.key_timestamp = time.time()
        self._update_last_access()

        stored = False
        if use_keychain and self.use_keychain and self.username != "default":
            metadata = {
                'stored_at': time.time(),
                'inactivity_timeout': self.inactivity_timeout
            }
            if self.keychain.store_encryption_key(self.username, key, metadata):
                stored = True
                if cache_to_keychain and self.cache_derived_key:
                    self.keychain.store_derived_key_cache(self.username, key, self.cache_ttl)

        if not stored:
            fallback_data = {
                'key': key.hex(),
                'inactivity_timeout': self.inactivity_timeout,
                'type': 'encryption_key'
            }
            self._store_to_fallback('enc_key', fallback_data)

    def get_encryption_key(self, from_keychain: bool = True, use_cache: bool = True) -> Optional[bytes]:
        if self.auto_lock_manager and self.auto_lock_manager.is_locked():
            return None

        if not self.encryption_key:
            key = None

            if from_keychain and self.use_keychain and self.username != "default":
                if use_cache and self.cache_derived_key:
                    key = self.keychain.get_derived_key_cache(self.username)

                if not key:
                    key = self.keychain.get_encryption_key(self.username)

            if not key:
                fallback_data = self._load_from_fallback('enc_key')
                if fallback_data:
                    key = bytes.fromhex(fallback_data['key'])

            if key:
                self.encryption_key = self.secure_memory.protect(key)
                self.key_timestamp = time.time()
                self._update_last_access()
                return key

            return None

        if self._is_expired():
            self.clear()
            return None

        self._update_last_access()
        return self.secure_memory.unprotect(self.encryption_key)

    def store_key_for_purpose(self, purpose: str, key: bytes, salt: bytes = None, use_keychain: bool = True):
        protected_key = self.secure_memory.protect(key)
        self._multi_keys[purpose] = {
            'key': protected_key,
            'timestamp': time.time(),
            'salt': salt.hex() if salt else None
        }
        self._update_last_access()

        stored = False
        if use_keychain and self.use_keychain and self.username != "default":
            key_data = {
                'key': key.hex(),
                'salt': salt.hex() if salt else None,
                'purpose': purpose
            }
            if self.keychain.store_key_for_purpose(self.username, purpose, key_data):
                stored = True

        if not stored:
            fallback_data = {
                'key': key.hex(),
                'salt': salt.hex() if salt else None,
                'purpose': purpose
            }
            self._store_to_fallback(f"key_{purpose}", fallback_data)

    def get_key_for_purpose(self, purpose: str, from_keychain: bool = True) -> Optional[bytes]:
        if self.auto_lock_manager and self.auto_lock_manager.is_locked():
            return None

        if purpose in self._multi_keys:
            key_data = self._multi_keys[purpose]
            if (time.time() - key_data['timestamp']) <= self.inactivity_timeout:
                self._update_last_access()
                return self.secure_memory.unprotect(key_data['key'])

        key = None
        if from_keychain and self.use_keychain and self.username != "default":
            key_data = self.keychain.get_key_for_purpose(self.username, purpose)
            if key_data:
                key = bytes.fromhex(key_data['key'])

        if not key:
            fallback_data = self._load_from_fallback(f"key_{purpose}")
            if fallback_data:
                key = bytes.fromhex(fallback_data['key'])

        if key:
            protected_key = self.secure_memory.protect(key)
            self._multi_keys[purpose] = {
                'key': protected_key,
                'timestamp': time.time(),
                'salt': None
            }
            self._update_last_access()

        return key

    def clear_key_for_purpose(self, purpose: str):
        if purpose in self._multi_keys:
            self.secure_memory.wipe(self._multi_keys[purpose]['key'])
            del self._multi_keys[purpose]

        if self.use_keychain and self.username != "default":
            self.keychain.delete_key_for_purpose(self.username, purpose)

        self._delete_fallback(f"key_{purpose}")

    def clear(self):
        if self.encryption_key:
            self.secure_memory.wipe(self.encryption_key)
            self.encryption_key = None

        for purpose, key_data in self._multi_keys.items():
            self.secure_memory.wipe(key_data['key'])
        self._multi_keys.clear()

        self.key_timestamp = 0.0
        self._last_access_time = time.time()

    def set_inactivity_timeout(self, seconds: int):
        self.inactivity_timeout = seconds
        if self.auto_lock_manager:
            self.auto_lock_manager.update_config({'inactivity_timeout': seconds})

    def set_username(self, username: str):
        self.username = username

    def store_auth_data(self, auth_hash: str, salt: bytes, params: dict, use_keychain: bool = True):
        stored = False
        if use_keychain and self.use_keychain and self.username != "default":
            if self.keychain.store_master_password_hash(self.username, auth_hash, salt, params):
                stored = True

        if not stored:
            fallback_data = {
                'auth_hash': auth_hash,
                'salt': salt.hex(),
                'params': params,
                'type': 'auth_data'
            }
            self._store_to_fallback('auth_data', fallback_data)

    def get_auth_data(self) -> tuple:
        if self.use_keychain and self.username != "default":
            data = self.keychain.get_master_password_hash(self.username)
            if data:
                return data.get('auth_hash'), data.get('salt'), data.get('params')

        fallback_data = self._load_from_fallback('auth_data')
        if fallback_data:
            return (
                fallback_data.get('auth_hash'),
                bytes.fromhex(fallback_data.get('salt', '')),
                fallback_data.get('params')
            )

        return None, None, None

    def store_session_data(self, session_data: Dict) -> bool:
        stored = False
        if self.use_keychain and self.username != "default":
            if self.keychain.store_session_data(self.username, session_data):
                stored = True

        if not stored:
            fallback_data = {
                'session_data': session_data,
                'type': 'session_data'
            }
            self._store_to_fallback('session_data', fallback_data)
            stored = True

        return stored

    def get_session_data(self) -> Optional[Dict]:
        if self.use_keychain and self.username != "default":
            data = self.keychain.get_session_data(self.username)
            if data:
                return data

        fallback_data = self._load_from_fallback('session_data')
        if fallback_data:
            return fallback_data.get('session_data')

        return None

    def clear_keychain(self):
        if self.use_keychain and self.username != "default":
            self.keychain.delete_credentials(self.username)

    def clear_encryption_key_from_keychain(self):
        if self.use_keychain and self.username != "default":
            self.keychain.delete_encryption_key(self.username)
            self.keychain.delete_derived_key_cache(self.username)

    def clear_all_fallback_data(self):
        key_types = ['enc_key', 'auth_data', 'session_data']
        for key_type in key_types:
            self._delete_fallback(key_type)

        for purpose in list(self._multi_keys.keys()):
            self._delete_fallback(f"key_{purpose}")

    def get_keychain_info(self) -> dict:
        info = {
            'available': self.keychain.is_available(),
            'enabled': self.use_keychain,
            'backend': self.keychain.get_current_backend(),
            'supported_backends': self.keychain.get_supported_backends(),
            'cache_enabled': self.cache_derived_key,
            'cache_ttl': self.cache_ttl,
            'fallback_available': True,
            'fallback_dir': str(self.fallback_dir),
            'stored_keys': list(self._multi_keys.keys())
        }

        if not self.keychain.is_available():
            info['error'] = self.keychain.get_last_error()

        return info

    def set_cache_options(self, enabled: bool, ttl_seconds: int = 3600):
        self.cache_derived_key = enabled
        self.cache_ttl = ttl_seconds

    def get_storage_status(self) -> Dict:
        status = {
            'keychain_available': self.keychain.is_available(),
            'keychain_enabled': self.use_keychain,
            'fallback_directory': str(self.fallback_dir),
            'fallback_files_exist': {},
            'cached_keys': list(self._multi_keys.keys()),
            'is_locked_by_auto_lock': self.auto_lock_manager.is_locked() if self.auto_lock_manager else False
        }

        key_types = ['enc_key', 'auth_data', 'session_data']
        for key_type in key_types:
            status['fallback_files_exist'][key_type] = self._get_fallback_path(key_type).exists()

        return status

    def get_auto_lock_status(self) -> Dict:
        if self.auto_lock_manager:
            return self.auto_lock_manager.get_status()
        return {'is_locked': False}