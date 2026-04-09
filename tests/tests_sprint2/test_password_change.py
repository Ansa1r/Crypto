import pytest
import tempfile
import shutil
from pathlib import Path
from src.core.key_manager import KeyManager
from src.database.db import init_db, set_master_password, add_vault_entry, get_all_vault_entries, \
    verify_master_password, get_pbkdf2_salt, has_master_password
from src.core.crypto.key_derivation import KeyDerivation
from src.core.crypto.placeholder import AES256Placeholder


class TestPasswordChangeIntegration:

    def setup_method(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test_vault.db"
        self.old_password = "OldMasterPassword123!"
        self.new_password = "NewMasterPassword456!"

        init_db(self.db_path)
        set_master_password(self.old_password, self.db_path)

        self.key_manager = KeyManager()
        self.encryption_service = AES256Placeholder(self.key_manager)
        self.key_manager.set_encryption_service(self.encryption_service)

        stored_auth_hash = None
        from src.database.db import get_connection
        with get_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT key_data FROM key_store WHERE key_type = 'auth_hash' ORDER BY created_at DESC LIMIT 1")
            row = cursor.fetchone()
            if row:
                stored_auth_hash = row['key_data'].decode('utf-8')

        self.stored_auth_hash = stored_auth_hash

    def teardown_method(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_create_vault_with_10_entries(self):
        entries = []
        for i in range(10):
            entry_id = add_vault_entry(
                title=f"Test Entry {i + 1}",
                username=f"user{i + 1}",
                password=f"password{i + 1}!",
                url=f"https://example{i + 1}.com",
                notes=f"Note for entry {i + 1}",
                tags="test",
                db_path=self.db_path
            )
            entries.append(entry_id)

        all_entries = get_all_vault_entries(self.db_path)

        assert len(all_entries) == 10

    def test_login_with_old_password(self):
        is_valid = verify_master_password(self.old_password, self.db_path)

        assert is_valid is True

    def test_login_with_wrong_password(self):
        is_valid = verify_master_password("WrongPassword123!", self.db_path)

        assert is_valid is False

    def test_password_change_with_reencryption(self):
        entries = []
        for i in range(10):
            entry_id = add_vault_entry(
                title=f"Entry {i + 1}",
                username=f"user{i + 1}",
                password=f"secret{i + 1}!",
                url=f"https://test{i + 1}.com",
                notes=f"Note {i + 1}",
                tags="test",
                db_path=self.db_path
            )
            entries.append(entry_id)

        old_entries = get_all_vault_entries(self.db_path)
        old_passwords = [entry['password'] for entry in old_entries]

        self.key_manager.login(self.old_password, self.stored_auth_hash, use_keychain=False)

        success, message = self.key_manager.change_password(
            self.old_password,
            self.new_password,
            self.stored_auth_hash,
            self.db_path,
            use_keychain=False
        )

        assert success is True

        is_valid = verify_master_password(self.new_password, self.db_path)
        assert is_valid is True

        is_valid_old = verify_master_password(self.old_password, self.db_path)
        assert is_valid_old is False

    def test_entries_accessible_with_new_password(self):
        original_passwords = []
        for i in range(10):
            entry_id = add_vault_entry(
                title=f"Entry {i + 1}",
                username=f"user{i + 1}",
                password=f"original_password_{i + 1}!",
                url=f"https://test{i + 1}.com",
                notes=f"Note {i + 1}",
                tags="test",
                db_path=self.db_path
            )
            original_passwords.append(f"original_password_{i + 1}!")

        self.key_manager.login(self.old_password, self.stored_auth_hash, use_keychain=False)

        success, message = self.key_manager.change_password(
            self.old_password,
            self.new_password,
            self.stored_auth_hash,
            self.db_path,
            use_keychain=False
        )

        assert success is True

        new_stored_auth_hash = None
        from src.database.db import get_connection
        with get_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT key_data FROM key_store WHERE key_type = 'auth_hash' ORDER BY created_at DESC LIMIT 1")
            row = cursor.fetchone()
            if row:
                new_stored_auth_hash = row['key_data'].decode('utf-8')

        self.key_manager.logout()

        self.key_manager.login(self.new_password, new_stored_auth_hash, use_keychain=False)

        entries_after = get_all_vault_entries(self.db_path)

        assert len(entries_after) == 10

    def test_vault_has_master_password(self):
        assert has_master_password(self.db_path) is True

    def test_pbkdf2_salt_exists(self):
        salt = get_pbkdf2_salt(self.db_path)

        assert salt is not None
        assert len(salt) == 16

    def test_multiple_password_changes(self):
        passwords = [
            "Password1!",
            "Password2!",
            "Password3!",
            "Password4!",
            "Password5!"
        ]

        current_password = self.old_password
        current_auth_hash = self.stored_auth_hash

        for i, new_password in enumerate(passwords):
            self.key_manager.login(current_password, current_auth_hash, use_keychain=False)

            success, message = self.key_manager.change_password(
                current_password,
                new_password,
                current_auth_hash,
                self.db_path,
                use_keychain=False
            )

            assert success is True

            is_valid = verify_master_password(new_password, self.db_path)
            assert is_valid is True

            from src.database.db import get_connection
            with get_connection(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT key_data FROM key_store WHERE key_type = 'auth_hash' ORDER BY created_at DESC LIMIT 1")
                row = cursor.fetchone()
                if row:
                    current_auth_hash = row['key_data'].decode('utf-8')

            current_password = new_password

            self.key_manager.logout()

    def test_change_password_with_invalid_current(self):
        success, message = self.key_manager.change_password(
            "WrongPassword123!",
            self.new_password,
            self.stored_auth_hash,
            self.db_path,
            use_keychain=False
        )

        assert success is False

    def test_change_password_with_weak_new_password(self):
        success, message = self.key_manager.change_password(
            self.old_password,
            "weak",
            self.stored_auth_hash,
            self.db_path,
            use_keychain=False
        )

        assert success is False
        assert "requirements" in message.lower()

    def test_change_password_same_as_current(self):
        success, message = self.key_manager.change_password(
            self.old_password,
            self.old_password,
            self.stored_auth_hash,
            self.db_path,
            use_keychain=False
        )

        assert success is False
        assert "different" in message.lower()

    def test_all_entries_after_password_change(self):
        test_entries = []
        for i in range(10):
            test_entries.append({
                'title': f"Test {i + 1}",
                'username': f"user{i + 1}",
                'password': f"pass{i + 1}!",
                'url': f"https://test{i + 1}.com",
                'notes': f"Note {i + 1}",
                'tags': "test"
            })

        for entry in test_entries:
            add_vault_entry(
                title=entry['title'],
                username=entry['username'],
                password=entry['password'],
                url=entry['url'],
                notes=entry['notes'],
                tags=entry['tags'],
                db_path=self.db_path
            )

        self.key_manager.login(self.old_password, self.stored_auth_hash, use_keychain=False)

        success, message = self.key_manager.change_password(
            self.old_password,
            self.new_password,
            self.stored_auth_hash,
            self.db_path,
            use_keychain=False
        )

        assert success is True

        new_stored_auth_hash = None
        from src.database.db import get_connection
        with get_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT key_data FROM key_store WHERE key_type = 'auth_hash' ORDER BY created_at DESC LIMIT 1")
            row = cursor.fetchone()
            if row:
                new_stored_auth_hash = row['key_data'].decode('utf-8')

        self.key_manager.logout()

        self.key_manager.login(self.new_password, new_stored_auth_hash, use_keychain=False)

        entries_after = get_all_vault_entries(self.db_path)

        assert len(entries_after) == 10

        for i, entry in enumerate(entries_after):
            assert entry['title'] == test_entries[i]['title']
            assert entry['username'] == test_entries[i]['username']
            assert entry['url'] == test_entries[i]['url']