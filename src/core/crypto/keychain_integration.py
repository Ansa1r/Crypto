import os
import json
from typing import Optional, Dict, Any
import keyring
from keyring.errors import PasswordSetError, PasswordDeleteError
from datetime import datetime


class KeychainIntegration:
    def __init__(self, app_name: str = "CryptoSafe"):
        self.app_name = app_name
        self._available = self._check_availability()
        self._last_error = None

    def _check_availability(self) -> bool:
        try:
            keyring.get_keyring()
            return True
        except Exception as e:
            self._last_error = str(e)
            return False

    def is_available(self) -> bool:
        return self._available

    def get_last_error(self) -> Optional[str]:
        return self._last_error

    def store_encryption_key(self, username: str, key: bytes, metadata: Optional[Dict] = None) -> bool:
        if not self._available:
            return False

        try:
            data = {
                'key': key.hex(),
                'timestamp': datetime.now().isoformat(),
                'type': 'encryption_key'
            }
            if metadata:
                data['metadata'] = metadata

            data_json = json.dumps(data)
            keyring.set_password(self.app_name, f"{username}_enc_key", data_json)
            return True
        except Exception as e:
            self._last_error = str(e)
            return False

    def get_encryption_key(self, username: str) -> Optional[bytes]:
        if not self._available:
            return None

        try:
            data_json = keyring.get_password(self.app_name, f"{username}_enc_key")
            if data_json:
                data = json.loads(data_json)
                return bytes.fromhex(data['key'])
            return None
        except Exception as e:
            self._last_error = str(e)
            return None

    def get_encryption_key_metadata(self, username: str) -> Optional[Dict]:
        if not self._available:
            return None

        try:
            data_json = keyring.get_password(self.app_name, f"{username}_enc_key")
            if data_json:
                data = json.loads(data_json)
                return {k: v for k, v in data.items() if k != 'key'}
            return None
        except Exception as e:
            self._last_error = str(e)
            return None

    def store_master_password_hash(self, username: str, auth_hash: str, salt: bytes, params: Dict) -> bool:
        if not self._available:
            return False

        try:
            data = {
                'auth_hash': auth_hash,
                'salt': salt.hex(),
                'params': params,
                'timestamp': datetime.now().isoformat(),
                'type': 'master_password_hash'
            }
            data_json = json.dumps(data)
            keyring.set_password(self.app_name, f"{username}_auth_hash", data_json)
            return True
        except Exception as e:
            self._last_error = str(e)
            return False

    def get_master_password_hash(self, username: str) -> Optional[Dict]:
        if not self._available:
            return None

        try:
            data_json = keyring.get_password(self.app_name, f"{username}_auth_hash")
            if data_json:
                data = json.loads(data_json)
                if 'salt' in data:
                    data['salt'] = bytes.fromhex(data['salt'])
                return data
            return None
        except Exception as e:
            self._last_error = str(e)
            return None

    def store_derived_key_cache(self, username: str, derived_key: bytes, ttl_seconds: int = 3600) -> bool:
        if not self._available:
            return False

        try:
            expires_at = datetime.now().timestamp() + ttl_seconds
            data = {
                'key': derived_key.hex(),
                'expires_at': expires_at,
                'created_at': datetime.now().isoformat(),
                'type': 'derived_key_cache'
            }
            data_json = json.dumps(data)
            keyring.set_password(self.app_name, f"{username}_derived_key", data_json)
            return True
        except Exception as e:
            self._last_error = str(e)
            return False

    def get_derived_key_cache(self, username: str) -> Optional[bytes]:
        if not self._available:
            return None

        try:
            data_json = keyring.get_password(self.app_name, f"{username}_derived_key")
            if data_json:
                data = json.loads(data_json)
                expires_at = data.get('expires_at', 0)
                if datetime.now().timestamp() < expires_at:
                    return bytes.fromhex(data['key'])
            return None
        except Exception as e:
            self._last_error = str(e)
            return None

    def store_session_data(self, username: str, session_data: Dict) -> bool:
        if not self._available:
            return False

        try:
            session_data['timestamp'] = datetime.now().isoformat()
            session_data['type'] = 'session_data'
            data_json = json.dumps(session_data)
            keyring.set_password(self.app_name, f"{username}_session", data_json)
            return True
        except Exception as e:
            self._last_error = str(e)
            return False

    def get_session_data(self, username: str) -> Optional[Dict]:
        if not self._available:
            return None

        try:
            data_json = keyring.get_password(self.app_name, f"{username}_session")
            if data_json:
                return json.loads(data_json)
            return None
        except Exception as e:
            self._last_error = str(e)
            return None

    def store_salt(self, username: str, salt: bytes) -> bool:
        if not self._available:
            return False

        try:
            salt_b64 = salt.hex()
            keyring.set_password(self.app_name, f"{username}_salt", salt_b64)
            return True
        except Exception as e:
            self._last_error = str(e)
            return False

    def get_salt(self, username: str) -> Optional[bytes]:
        if not self._available:
            return None

        try:
            salt_b64 = keyring.get_password(self.app_name, f"{username}_salt")
            if salt_b64:
                return bytes.fromhex(salt_b64)
            return None
        except Exception as e:
            self._last_error = str(e)
            return None

    def store_parameters(self, username: str, params: Dict[str, Any]) -> bool:
        if not self._available:
            return False

        try:
            params_json = json.dumps(params)
            keyring.set_password(self.app_name, f"{username}_params", params_json)
            return True
        except Exception as e:
            self._last_error = str(e)
            return False

    def get_parameters(self, username: str) -> Optional[Dict[str, Any]]:
        if not self._available:
            return None

        try:
            params_json = keyring.get_password(self.app_name, f"{username}_params")
            if params_json:
                return json.loads(params_json)
            return None
        except Exception as e:
            self._last_error = str(e)
            return None

    def delete_credentials(self, username: str) -> bool:
        if not self._available:
            return False

        success = True
        services = [
            f"{username}_enc_key",
            f"{username}_auth_hash",
            f"{username}_salt",
            f"{username}_params",
            f"{username}_derived_key",
            f"{username}_session"
        ]

        for service in services:
            try:
                keyring.delete_password(self.app_name, service)
            except Exception:
                pass

        return success

    def delete_encryption_key(self, username: str) -> bool:
        if not self._available:
            return False

        try:
            keyring.delete_password(self.app_name, f"{username}_enc_key")
            return True
        except Exception:
            return False

    def delete_derived_key_cache(self, username: str) -> bool:
        if not self._available:
            return False

        try:
            keyring.delete_password(self.app_name, f"{username}_derived_key")
            return True
        except Exception:
            return False

    def get_supported_backends(self) -> list:
        if not self._available:
            return []

        try:
            backends = keyring.backend.get_all_keyring()
            return [backend.name for backend in backends if backend.available]
        except Exception:
            return []

    def get_current_backend(self) -> Optional[str]:
        if not self._available:
            return None

        try:
            current = keyring.get_keyring()
            return current.name if current else None
        except Exception:
            return None