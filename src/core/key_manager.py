from crypto.abstract import KeyManager
from crypto.key_derivation import KeyDerivation
from crypto.secure_memory import secure_zero, ProtectedMemory
from crypto.password_validator import PasswordValidator
from crypto.key_storage import KeychainStorage, SecureKeyCache
from crypto.authentication import SessionManager, ExponentialBackoff
import time
import json
import secrets
from typing import Optional
from src.database.db import get_connection

class MasterKeyManager(KeyManager):
    def __init__(self, config=None):
        self._encryption_key = None
        self._unlocked = False
        self._unlock_time = None
        self._last_activity = None
        self.key_derivation = KeyDerivation(config)
        self.validator = PasswordValidator(config)
        self.session_manager = SessionManager()
        self.keychain = KeychainStorage(config.get('use_keychain', True) if config else True)
        self.key_cache = SecureKeyCache(timeout=3600)
        self.backoff = ExponentialBackoff()
        self._protected_key = None
        self._current_username = None
        self._auth_params = None
        self._encryption_params = None

    def get_encryption_key(self):
        if self.is_unlocked():
            self._update_activity()
            self.session_manager.update_activity()
            cached = self.key_cache.get("current_key")
            if cached:
                return cached
            return self._encryption_key
        return None

    def is_unlocked(self):
        if not self._unlocked:
            return False

        if not self.session_manager.is_valid():
            self.lock()
            return False

        if time.time() - self._last_activity > 3600:
            self.lock()
            return False

        return True

    def unlock(self, password, auth_hash, pbkdf2_salt, username="default"):
        if not self.backoff.can_attempt():
            return False

        if not self.key_derivation.verify_password(password, auth_hash):
            self.backoff.record_attempt()
            return False

        key = self.key_derivation.derive_encryption_key(password, pbkdf2_salt)

        with ProtectedMemory(key) as protected:
            self._encryption_key = bytes(protected)
            self._protected_key = protected
            self.key_cache.set("current_key", self._encryption_key)

        self._unlocked = True
        self._unlock_time = time.time()
        self._update_activity()
        self.session_manager.create_session(username)
        self._current_username = username
        self.backoff.reset()

        keychain_key = self.keychain.retrieve_key("encryption_key", username)
        if not keychain_key:
            self.keychain.store_key("encryption_key", self._encryption_key, username)

        return True

    def unlock_with_keychain(self, username="default"):
        stored_key = self.keychain.retrieve_key("encryption_key", username)
        if not stored_key:
            return False

        with ProtectedMemory(stored_key) as protected:
            self._encryption_key = bytes(protected)
            self._protected_key = protected
            self.key_cache.set("current_key", self._encryption_key)

        self._unlocked = True
        self._unlock_time = time.time()
        self._update_activity()
        self.session_manager.create_session(username)
        self._current_username = username
        self.backoff.reset()

        return True

    def lock(self):
        if self._encryption_key:
            secure_zero(self._encryption_key)
        self._encryption_key = None
        self._protected_key = None
        self._unlocked = False
        self.session_manager.destroy_session()
        self.key_cache.clear_all()
        self._current_username = None

    def verify_current_password(self, password, auth_hash):
        return self.key_derivation.verify_password(password, auth_hash)

    def derive_new_key(self, password, pbkdf2_salt):
        return self.key_derivation.derive_encryption_key(password, pbkdf2_salt)

    def create_vault(self, password, db_path, username="default"):
        valid, errors = self.validator.validate(password)
        if not valid:
            raise ValueError(f"Password too weak: {', '.join(errors)}")

        auth_hash, auth_params = self.key_derivation.create_auth_hash(password)
        pbkdf2_salt = secrets.token_bytes(16)
        encryption_params = self.key_derivation.create_encryption_params()

        self.keychain.clear_all_keys(username)

        with get_connection(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                DELETE FROM key_store 
                WHERE key_type IN ('auth_hash', 'pbkdf2_salt', 'auth_params', 'encryption_params') 
                AND username = ?
            """, (username,))

            cursor.execute("""
                INSERT INTO key_store (key_type, key_data, params, username)
                VALUES (?, ?, ?, ?)
            """, ('auth_hash', auth_hash.encode('utf-8'), json.dumps(auth_params), username))

            cursor.execute("""
                INSERT INTO key_store (key_type, key_data, params, username)
                VALUES (?, ?, ?, ?)
            """, ('pbkdf2_salt', pbkdf2_salt, json.dumps(encryption_params), username))

            cursor.execute("""
                INSERT INTO key_store (key_type, key_data, params, username)
                VALUES (?, ?, ?, ?)
            """, ('auth_params', json.dumps(auth_params).encode('utf-8'), None, username))

            cursor.execute("""
                INSERT INTO key_store (key_type, key_data, params, username)
                VALUES (?, ?, ?, ?)
            """, ('encryption_params', json.dumps(encryption_params).encode('utf-8'), None, username))

            conn.commit()

        return auth_hash, pbkdf2_salt

    def change_master_password(self, old_password, new_password, auth_hash, pbkdf2_salt, db_path, crypto_service,
                               username="default"):
        if not self.verify_current_password(old_password, auth_hash):
            return False, None, None

        valid, errors = self.validator.validate(new_password)
        if not valid:
            raise ValueError(f"New password too weak: {', '.join(errors)}")

        old_key = self.get_encryption_key()
        new_key = self.derive_new_key(new_password, pbkdf2_salt)

        self._reencrypt_all_entries(old_key, new_key, crypto_service, db_path)

        new_auth_hash, new_auth_params = self.key_derivation.create_auth_hash(new_password)
        new_encryption_params = self.key_derivation.create_encryption_params()

        with get_connection(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                DELETE FROM key_store 
                WHERE key_type IN ('auth_hash', 'auth_params', 'encryption_params') 
                AND username = ?
            """, (username,))

            cursor.execute("""
                INSERT INTO key_store (key_type, key_data, params, username)
                VALUES (?, ?, ?, ?)
            """, ('auth_hash', new_auth_hash.encode('utf-8'), json.dumps(new_auth_params), username))

            cursor.execute("""
                INSERT INTO key_store (key_type, key_data, params, username)
                VALUES (?, ?, ?, ?)
            """, ('auth_params', json.dumps(new_auth_params).encode('utf-8'), None, username))

            cursor.execute("""
                INSERT INTO key_store (key_type, key_data, params, username)
                VALUES (?, ?, ?, ?)
            """, ('encryption_params', json.dumps(new_encryption_params).encode('utf-8'), None, username))

            conn.commit()

        self.keychain.store_key("encryption_key", new_key, username)

        return True, new_auth_hash, pbkdf2_salt

    def _reencrypt_all_entries(self, old_key, new_key, crypto_service, db_path):
        from src.database.db import get_all_vault_entries, update_vault_entry

        entries = get_all_vault_entries(db_path)
        for entry in entries:
            if entry.get('encrypted_password'):
                try:
                    decrypted = crypto_service.decrypt(entry['encrypted_password'])
                    reencrypted = crypto_service.encrypt(decrypted)
                    update_vault_entry(entry['id'], encrypted_password=reencrypted, db_path=db_path)
                except Exception as e:
                    print(f"Failed to re-encrypt entry {entry['id']}: {e}")
                    continue

    def _update_activity(self):
        self._last_activity = time.time()
        if self.session_manager.current_session:
            self.session_manager.update_activity()

    def get_remaining_lock_time(self) -> float:
        return self.backoff.get_delay()

    def can_attempt_login(self) -> bool:
        return self.backoff.can_attempt()

    def get_session_info(self):
        return self.session_manager.get_session_info()

    def remove_from_keychain(self, username="default"):
        self.keychain.delete_key("encryption_key", username)

    def is_keychain_available(self) -> bool:
        return self.keychain.use_keychain

    def get_auth_params(self, db_path, username="default"):
        with get_connection(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT key_data FROM key_store 
                WHERE key_type = 'auth_params' 
                AND username = ?
                ORDER BY created_at DESC LIMIT 1
            """, (username,))
            row = cursor.fetchone()
            if row:
                return json.loads(row['key_data'].decode('utf-8'))
            return None

    def get_encryption_params(self, db_path, username="default"):
        with get_connection(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT key_data FROM key_store 
                WHERE key_type = 'encryption_params' 
                AND username = ?
                ORDER BY created_at DESC LIMIT 1
            """, (username,))
            row = cursor.fetchone()
            if row:
                return json.loads(row['key_data'].decode('utf-8'))
            return None