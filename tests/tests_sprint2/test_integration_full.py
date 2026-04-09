import pytest
import tempfile
import shutil
from pathlib import Path
from src.core.key_manager import KeyManager
from src.database.db import init_db, set_master_password, add_vault_entry, get_all_vault_entries, \
    verify_master_password, has_master_password, get_connection
from src.core.crypto.placeholder import AES256Placeholder


class TestFullIntegration:

    def setup_method(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test_vault.db"
        self.master_password = "MasterPassword123!"

        init_db(self.db_path)
        set_master_password(self.master_password, self.db_path)

        self.key_manager = KeyManager()
        self.encryption_service = AES256Placeholder(self.key_manager)
        self.key_manager.set_encryption_service(self.encryption_service)

        from src.database.db import get_connection
        with get_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT key_data FROM key_store WHERE key_type = 'auth_hash' ORDER BY created_at DESC LIMIT 1")
            row = cursor.fetchone()
            self.stored_auth_hash = row['key_data'].decode('utf-8') if row else None

    def teardown_method(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_complete_workflow(self):
        assert has_master_password(self.db_path) is True

        login_success = self.key_manager.login(self.master_password, self.stored_auth_hash, use_keychain=False)
        assert login_success is True

        entry_id = add_vault_entry(
            title="Google Account",
            username="user@gmail.com",
            password="SecretPass123!",
            url="https://google.com",
            notes="My Google account",
            tags="email,work",
            db_path=self.db_path
        )
        assert entry_id > 0

        entry_id2 = add_vault_entry(
            title="GitHub",
            username="devuser",
            password="GitHubPass456!",
            url="https://github.com",
            notes="Development account",
            tags="dev,github",
            db_path=self.db_path
        )
        assert entry_id2 > 0

        entries = get_all_vault_entries(self.db_path)
        assert len(entries) == 2

        new_password = "NewStrongPassword789!"

        success, message = self.key_manager.change_password(
            self.master_password,
            new_password,
            self.stored_auth_hash,
            self.db_path,
            use_keychain=False
        )
        assert success is True

        with get_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT key_data FROM key_store WHERE key_type = 'auth_hash' ORDER BY created_at DESC LIMIT 1")
            row = cursor.fetchone()
            new_stored_auth_hash = row['key_data'].decode('utf-8') if row else None

        self.key_manager.logout()

        login_success = self.key_manager.login(new_password, new_stored_auth_hash, use_keychain=False)
        assert login_success is True

        entries_after = get_all_vault_entries(self.db_path)
        assert len(entries_after) == 2

        self.key_manager.logout()

        is_valid_old = verify_master_password(self.master_password, self.db_path)
        assert is_valid_old is False

        is_valid_new = verify_master_password(new_password, self.db_path)
        assert is_valid_new is True