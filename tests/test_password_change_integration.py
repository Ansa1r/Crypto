import pytest
import os
import tempfile
import shutil
from src.core.key_manager import MasterKeyManager
from src.core.crypto.placeholder import AES256Placeholder
from src.database.db import (
    init_db, add_vault_entry, get_all_vault_entries,
    set_master_password, verify_master_password,
    get_pbkdf2_salt, get_connection
)


@pytest.fixture
def temp_db():
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test_cryptosafe.db")

    init_db(db_path)

    yield db_path

    if os.path.exists(db_path):
        os.remove(db_path)
    shutil.rmtree(temp_dir)


@pytest.fixture
def key_manager():
    return MasterKeyManager()


@pytest.fixture
def crypto_service(key_manager):
    return AES256Placeholder(key_manager)


def create_test_entries(db_path, count=10):
    entries = []
    for i in range(count):
        entry_id = add_vault_entry(
            title=f"Test Entry {i}",
            username=f"user{i}",
            password=f"password{i}_secret!",
            url=f"https://example{i}.com",
            notes=f"Notes for entry {i}",
            tags=f"test,entry{i}",
            db_path=db_path
        )
        entries.append(entry_id)
    return entries


def test_password_change_workflow(temp_db, key_manager, crypto_service):
    original_password = "OriginalPassword123!"
    new_password = "NewStrongPassword456!"

    auth_hash, pbkdf2_salt = key_manager.create_vault(original_password, temp_db, "testuser")

    assert verify_master_password(original_password, temp_db, "testuser") is True

    entry_ids = create_test_entries(temp_db, 5)

    unlock_success = key_manager.unlock(original_password, auth_hash, pbkdf2_salt, "testuser")
    assert unlock_success is True

    change_success, new_auth_hash, new_salt = key_manager.change_master_password(
        original_password, new_password, auth_hash, pbkdf2_salt,
        temp_db, crypto_service, "testuser"
    )

    assert change_success is True
    assert new_auth_hash is not None
    assert new_salt == pbkdf2_salt

    key_manager.lock()

    unlock_with_new = key_manager.unlock(new_password, new_auth_hash, pbkdf2_salt, "testuser")
    assert unlock_with_new is True


def test_password_change_with_entries_accessible(temp_db, key_manager, crypto_service):
    original_password = "StartPass123!"
    new_password = "ChangedPass456!"

    auth_hash, pbkdf2_salt = key_manager.create_vault(original_password, temp_db)

    entry_data = []
    for i in range(10):
        data = f"SecretData{i}_with_special_chars!@#"
        entry_id = add_vault_entry(
            title=f"Secure Entry {i}",
            username=f"secure_user{i}",
            password=data,
            url=f"https://secure{i}.com",
            notes="encrypted_note",
            tags="secure",
            db_path=temp_db
        )
        entry_data.append((entry_id, data))

    key_manager.unlock(original_password, auth_hash, pbkdf2_salt)

    change_success, new_auth_hash, _ = key_manager.change_master_password(
        original_password, new_password, auth_hash, pbkdf2_salt,
        temp_db, crypto_service
    )
    assert change_success is True

    key_manager.lock()

    key_manager.unlock(new_password, new_auth_hash, pbkdf2_salt)

    entries = get_all_vault_entries(temp_db)
    assert len(entries) == 10


def test_password_change_with_rollback_on_failure(temp_db, key_manager, crypto_service):
    original_password = "Original123!"
    new_password = "NewPassword456!"

    auth_hash, pbkdf2_salt = key_manager.create_vault(original_password, temp_db)

    entry_ids = create_test_entries(temp_db, 3)

    key_manager.unlock(original_password, auth_hash, pbkdf2_salt)

    with get_connection(temp_db) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE vault_entries SET encrypted_password = NULL WHERE id = ?
        """, (entry_ids[1],))
        conn.commit()

    change_success, new_auth_hash, _ = key_manager.change_master_password(
        original_password, new_password, auth_hash, pbkdf2_salt,
        temp_db, crypto_service
    )

    assert change_success is False

    with get_connection(temp_db) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT key_data FROM key_store WHERE key_type = 'auth_hash'")
        row = cursor.fetchone()
        stored_hash = row['key_data'].decode('utf-8')

        assert stored_hash == auth_hash


def test_password_change_with_keychain_fallback(temp_db, key_manager, crypto_service):
    original_password = "KeychainPass123!"
    new_password = "NewKeychainPass456!"

    key_manager.keychain.use_keychain = False

    auth_hash, pbkdf2_salt = key_manager.create_vault(original_password, temp_db)

    entry_ids = create_test_entries(temp_db, 2)

    key_manager.unlock(original_password, auth_hash, pbkdf2_salt)

    key_manager.keychain.store_key("encryption_key", key_manager.get_encryption_key())

    change_success, new_auth_hash, _ = key_manager.change_master_password(
        original_password, new_password, auth_hash, pbkdf2_salt,
        temp_db, crypto_service
    )

    assert change_success is True

    stored_key = key_manager.keychain.retrieve_key("encryption_key")
    assert stored_key is not None


def test_password_change_multiple_times(temp_db, key_manager, crypto_service):
    passwords = [
        "FirstPass123!",
        "SecondPass456!",
        "ThirdPass789!",
        "FourthPass012!"
    ]

    current_auth_hash, current_salt = key_manager.create_vault(passwords[0], temp_db)

    create_test_entries(temp_db, 2)

    for i in range(1, len(passwords)):
        key_manager.unlock(passwords[i - 1], current_auth_hash, current_salt)

        success, new_auth_hash, _ = key_manager.change_master_password(
            passwords[i - 1], passwords[i], current_auth_hash, current_salt,
            temp_db, crypto_service
        )

        assert success is True

        current_auth_hash = new_auth_hash

        key_manager.lock()

    final_unlock = key_manager.unlock(passwords[-1], current_auth_hash, current_salt)
    assert final_unlock is True


def test_password_change_with_unicode(temp_db, key_manager, crypto_service):
    original_password = "пароль123!@#"
    new_password = "новый_пароль_456$%^"

    auth_hash, pbkdf2_salt = key_manager.create_vault(original_password, temp_db)

    create_test_entries(temp_db, 2)

    key_manager.unlock(original_password, auth_hash, pbkdf2_salt)

    success, new_auth_hash, _ = key_manager.change_master_password(
        original_password, new_password, auth_hash, pbkdf2_salt,
        temp_db, crypto_service
    )

    assert success is True

    key_manager.lock()

    unlock_success = key_manager.unlock(new_password, new_auth_hash, pbkdf2_salt)
    assert unlock_success is True