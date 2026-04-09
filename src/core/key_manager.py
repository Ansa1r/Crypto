from typing import Optional, Dict, List
from pathlib import Path
from src.core.crypto.key_derivation import KeyDerivation, KeyPurpose
from src.core.crypto.authentication import AuthenticationService
from src.core.crypto.key_storage import KeyStorage
from src.core.crypto.multi_key_manager import MultiKeyManager
from src.core.crypto.auto_lock_manager import AutoLockManager, LockReason
from src.core.crypto.aes_gcm import AES256GCMEncryptionService
from src.core.config import ConfigManager
from datetime import datetime


class KeyManager:
    def __init__(self, config: Optional[ConfigManager] = None, username: str = "default",
                 fallback_dir: Optional[Path] = None):
        self.config = config or ConfigManager()
        self.username = username
        self.key_derivation = KeyDerivation()
        self.authentication = AuthenticationService(self.key_derivation)
        self.auto_lock_manager = AutoLockManager(key_manager=self)
        self.key_storage = KeyStorage(username, fallback_dir, self.auto_lock_manager)
        self.multi_key_manager = MultiKeyManager(self.key_derivation, username)
        self._current_auth_hash = None
        self._current_salt = None
        self._fast_unlock_enabled = True
        self._use_fallback = not self.key_storage.is_keychain_available()
        self._encryption_service = None
        self._auto_lock_configured = False

    def set_encryption_service(self, encryption_service):
        self._encryption_service = encryption_service

    def get_encryption_service(self):
        if self._encryption_service is None:
            self._encryption_service = AES256GCMEncryptionService(self)
        return self._encryption_service

    def initialize_vault(self, master_password: str, use_keychain: bool = True, store_in_keychain: bool = True):
        auth_hash, salt = self.key_derivation.create_auth_hash(master_password)
        self._current_auth_hash = auth_hash
        self._current_salt = salt
        enc_key = self.key_derivation.derive_encryption_key(master_password, salt)

        use_keychain_final = use_keychain and store_in_keychain and self.key_storage.is_keychain_available()
        self.key_storage.store_encryption_key(enc_key, use_keychain_final, store_in_keychain)

        self.multi_key_manager.derive_and_store_key(enc_key, KeyPurpose.VAULT_ENCRYPTION, use_keychain_final)
        self.multi_key_manager.derive_and_store_key(enc_key, KeyPurpose.AUDIT_LOG_SIGNING, use_keychain_final)

        store_auth = store_in_keychain and use_keychain_final
        self.key_storage.store_auth_data(auth_hash, salt, {}, store_auth)

        session_data = {
            'username': self.username,
            'initialized_at': self.key_storage.key_timestamp,
            'use_keychain': use_keychain_final,
            'use_fallback': not use_keychain_final
        }
        self.key_storage.store_session_data(session_data)

        return auth_hash, salt

    def login(self, master_password: str, stored_auth_hash: str, use_keychain: bool = True,
              cache_key: bool = True) -> bool:
        success, enc_key = self.authentication.verify_master_password(master_password, stored_auth_hash)
        if success and enc_key:
            use_keychain_final = use_keychain and self.key_storage.is_keychain_available()
            self.key_storage.store_encryption_key(enc_key, use_keychain_final, cache_key)

            self.multi_key_manager.derive_and_store_key(enc_key, KeyPurpose.VAULT_ENCRYPTION, use_keychain_final)
            self.multi_key_manager.derive_and_store_key(enc_key, KeyPurpose.AUDIT_LOG_SIGNING, use_keychain_final)

            self.auto_lock_manager.unlock()

            return True
        return False

    def fast_unlock(self) -> bool:
        if not self._fast_unlock_enabled:
            return False

        enc_key = self.key_storage.get_encryption_key(from_keychain=True, use_cache=True)
        if enc_key:
            auth_data = self.key_storage.get_auth_data()
            if auth_data:
                self._current_auth_hash, self._current_salt, _ = auth_data

            self.multi_key_manager.derive_and_cache_key(enc_key, KeyPurpose.VAULT_ENCRYPTION)
            self.multi_key_manager.derive_and_cache_key(enc_key, KeyPurpose.AUDIT_LOG_SIGNING)

            self.auto_lock_manager.unlock()

            return True

        return False

    def login_from_storage(self, use_cache: bool = True) -> bool:
        auth_hash, salt, params = self.key_storage.get_auth_data()

        if not auth_hash or not salt:
            return False

        self._current_auth_hash = auth_hash
        self._current_salt = salt

        enc_key = self.key_storage.get_encryption_key(from_keychain=True, use_cache=use_cache)
        if enc_key:
            self.multi_key_manager.derive_and_cache_key(enc_key, KeyPurpose.VAULT_ENCRYPTION)
            self.multi_key_manager.derive_and_cache_key(enc_key, KeyPurpose.AUDIT_LOG_SIGNING)
            self.auto_lock_manager.unlock()
            return True

        return False

    def get_encryption_key(self) -> Optional[bytes]:
        return self.key_storage.get_encryption_key()

    def get_key_for_purpose(self, purpose: KeyPurpose) -> Optional[bytes]:
        enc_key = self.get_encryption_key()
        if enc_key:
            return self.multi_key_manager.derive_and_cache_key(enc_key, purpose)
        return None

    def get_audit_signing_key(self) -> Optional[bytes]:
        return self.get_key_for_purpose(KeyPurpose.AUDIT_LOG_SIGNING)

    def get_sharing_key(self) -> Optional[bytes]:
        return self.get_key_for_purpose(KeyPurpose.SECURE_SHARING)

    def get_backup_key(self) -> Optional[bytes]:
        return self.get_key_for_purpose(KeyPurpose.BACKUP_ENCRYPTION)

    def get_session_key(self) -> Optional[bytes]:
        return self.get_key_for_purpose(KeyPurpose.SESSION_KEY)

    def logout(self, clear_keychain: bool = False, clear_cache: bool = True, clear_fallback: bool = False,
               reason: LockReason = LockReason.MANUAL):
        self.key_storage.clear()
        self.multi_key_manager.clear_key_cache()
        self.authentication.logout()

        if clear_keychain:
            self.key_storage.clear_keychain()
        elif clear_cache:
            self.key_storage.clear_encryption_key_from_keychain()

        if clear_fallback:
            self.key_storage.clear_all_fallback_data()

        self.auto_lock_manager.lock(reason)

    def lock_vault(self, reason: LockReason = LockReason.MANUAL, details: str = None) -> bool:
        return self.auto_lock_manager.lock(reason, details)

    def unlock_vault(self) -> bool:
        return self.auto_lock_manager.unlock()

    def is_vault_locked(self) -> bool:
        return self.auto_lock_manager.is_locked()

    def update_activity(self):
        self.auto_lock_manager.update_activity()
        self.authentication.update_activity()

    def on_window_minimized(self):
        self.auto_lock_manager.on_window_minimized()

    def on_window_background(self):
        self.auto_lock_manager.on_window_background()

    def on_system_sleep(self):
        self.auto_lock_manager.on_system_sleep()

    def on_screen_lock(self):
        self.auto_lock_manager.on_screen_lock()

    def get_auto_lock_status(self) -> Dict:
        return self.auto_lock_manager.get_status()

    def get_lock_history(self, limit: int = 10) -> list:
        return self.auto_lock_manager.get_lock_history(limit)

    def configure_auto_lock(self, enabled: bool = None, timeout: int = None,
                            lock_on_minimize: bool = None, lock_on_background: bool = None,
                            lock_on_system_sleep: bool = None, lock_on_screen_lock: bool = None):
        config = {}
        if enabled is not None:
            config['auto_lock_enabled'] = enabled
        if timeout is not None:
            config['inactivity_timeout'] = timeout
            self.key_storage.set_inactivity_timeout(timeout)
        if lock_on_minimize is not None:
            config['lock_on_minimize'] = lock_on_minimize
        if lock_on_background is not None:
            config['lock_on_background'] = lock_on_background
        if lock_on_system_sleep is not None:
            config['lock_on_system_sleep'] = lock_on_system_sleep
        if lock_on_screen_lock is not None:
            config['lock_on_screen_lock'] = lock_on_screen_lock

        if config:
            self.auto_lock_manager.update_config(config)
            self._auto_lock_configured = True

    def change_password(self, current_password: str, new_password: str, stored_auth_hash: str,
                        db_path: Path, use_keychain: bool = True, cache_key: bool = True,
                        progress_callback=None, pause_check_callback=None) -> tuple:

        if not self.login(current_password, stored_auth_hash):
            return False, "Current password is incorrect"

        old_key = self.get_encryption_key()
        if not old_key:
            return False, "Could not retrieve encryption key"

        is_valid, errors = self.key_derivation.validate_password_strength(new_password)
        if not is_valid:
            return False, f"New password does not meet requirements: {', '.join(errors)}"

        if new_password == current_password:
            return False, "New password must be different from current password"

        backup_path = None
        try:
            from src.database.db import backup_db, get_all_vault_entries, update_vault_entry

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = Path.home() / ".cryptosafe" / "checkpoints" / f"vault_backup_{timestamp}.db"
            backup_path.parent.mkdir(parents=True, exist_ok=True)
            backup_db(backup_path, db_path)

            all_entries = get_all_vault_entries(db_path)
            total_entries = len(all_entries)

            new_auth_hash, new_salt = self.key_derivation.create_auth_hash(new_password)
            new_enc_key = self.key_derivation.derive_encryption_key(new_password, new_salt)

            if progress_callback:
                progress_callback(0, total_entries, "Starting re-encryption...", 0, 0)

            encryption_service = self.get_encryption_service()

            for idx, entry in enumerate(all_entries):
                if pause_check_callback:
                    pause_check_callback()

                if progress_callback:
                    progress_callback(idx + 1, total_entries, f"Re-encrypting: {entry.get('title', 'Unknown')}",
                                      idx, 0)

                decrypted_password = self._decrypt_entry_password(entry.get('password', ''), old_key, encryption_service)
                if decrypted_password is None:
                    continue

                encrypted_password = self._encrypt_entry_password(decrypted_password, new_enc_key, encryption_service)
                if encrypted_password is None:
                    continue

                update_vault_entry(
                    entry_id=entry['id'],
                    password=encrypted_password,
                    db_path=db_path
                )

            use_keychain_final = use_keychain and self.key_storage.is_keychain_available()
            self.key_storage.store_encryption_key(new_enc_key, use_keychain_final, cache_key)
            self._current_auth_hash = new_auth_hash
            self._current_salt = new_salt

            self.multi_key_manager.derive_and_store_key(new_enc_key, KeyPurpose.VAULT_ENCRYPTION, use_keychain_final)
            self.multi_key_manager.derive_and_store_key(new_enc_key, KeyPurpose.AUDIT_LOG_SIGNING, use_keychain_final)

            self.key_storage.store_auth_data(new_auth_hash, new_salt, {}, use_keychain_final)

            if backup_path and backup_path.exists():
                backup_path.unlink()

            if progress_callback:
                progress_callback(total_entries, total_entries, "Password changed successfully", total_entries, 0)

            return True, f"Password changed successfully. Processed {total_entries} entries."

        except Exception as e:
            if backup_path and backup_path.exists():
                from src.database.db import restore_db
                restore_db(backup_path, db_path)
            return False, f"Error during password change: {str(e)}"

    def _decrypt_entry_password(self, encrypted_password: str, key: bytes, encryption_service) -> Optional[str]:
        try:
            if not encrypted_password or encrypted_password == '':
                return ''

            if encryption_service:
                encrypted_bytes = bytes.fromhex(encrypted_password)
                decrypted_bytes = encryption_service.decrypt(encrypted_bytes)
                return decrypted_bytes.decode('utf-8')
            else:
                return encrypted_password
        except Exception:
            return None

    def _encrypt_entry_password(self, password: str, key: bytes, encryption_service) -> Optional[str]:
        try:
            if not password:
                return ''

            if encryption_service:
                encrypted_bytes = encryption_service.encrypt(password.encode('utf-8'))
                return encrypted_bytes.hex()
            else:
                return password
        except Exception:
            return None

    def is_locked(self) -> bool:
        return self.get_encryption_key() is None or self.auto_lock_manager.is_locked()

    def enable_keychain(self, enable: bool):
        self.key_storage.enable_keychain(enable)
        self._use_fallback = not (enable and self.key_storage.is_keychain_available())

    def is_keychain_available(self) -> bool:
        return self.key_storage.is_keychain_available()

    def get_keychain_error(self) -> Optional[str]:
        return self.key_storage.get_keychain_error()

    def get_keychain_info(self) -> dict:
        return self.key_storage.get_keychain_info()

    def get_storage_status(self) -> dict:
        return self.key_storage.get_storage_status()

    def set_username(self, username: str):
        self.username = username
        self.key_storage.set_username(username)
        self.multi_key_manager = MultiKeyManager(self.key_derivation, username)

    def enable_fast_unlock(self, enable: bool):
        self._fast_unlock_enabled = enable

    def set_cache_options(self, enabled: bool, ttl_seconds: int = 3600):
        self.key_storage.set_cache_options(enabled, ttl_seconds)

    def get_session_info(self) -> Optional[Dict]:
        return self.key_storage.get_session_data()

    def is_using_fallback(self) -> bool:
        return not self.key_storage.is_keychain_available() or not self.key_storage.use_keychain

    def get_available_key_types(self) -> List[Dict]:
        return self.multi_key_manager.get_available_key_types()

    def get_key_purposes(self) -> List[Dict]:
        return self.multi_key_manager.get_key_purposes()