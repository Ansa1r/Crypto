import pytest
from src.database.db import (
    add_vault_entry,
    get_vault_entry,
    update_vault_entry,
    get_connection
)

def test_init_db_creates_tables(test_db):
    with get_connection(db_path=test_db) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = {row[0] for row in cursor.fetchall()}
        expected = {"vault_entries", "audit_log", "settings", "key_store"}
        assert expected.issubset(tables)

def test_add_and_get_vault_entry(test_db, placeholder_key, crypto_service):
    entry_id = add_vault_entry(
        title="Test Site",
        username="user123",
        password="SecretPass123",
        url="https://example.com",
        notes="Some important note",
        tags="work,important",
        key=placeholder_key,
        db_path=test_db
    )
    assert entry_id > 0

    entry = get_vault_entry(entry_id, key=placeholder_key, db_path=test_db)
    assert entry is not None
    assert entry["title"] == "Test Site"
    assert entry["username"] == "user123"
    assert entry["password"] == "SecretPass123"
    assert entry["url"] == "https://example.com"
    assert entry["notes"] == "Some important note"
    assert entry["tags"] == "work,important"

def test_update_vault_entry(test_db, placeholder_key):
    entry_id = add_vault_entry(
        title="Old Title",
        username="olduser",
        password="oldpass",
        url="old.url",
        notes="old note",
        tags="old",
        key=placeholder_key,
        db_path=test_db
    )

    update_vault_entry(
        entry_id=entry_id,
        title="New Title",
        password="NewSuperPass456",
        notes=None,
        tags="new,updated",
        key=placeholder_key,
        db_path=test_db
    )

    updated = get_vault_entry(entry_id, key=placeholder_key, db_path=test_db)
    assert updated["title"] == "New Title"
    assert updated["password"] == "NewSuperPass456"
    assert updated["notes"] is None
    assert updated["tags"] == "new,updated"
    assert updated["username"] == "olduser"
    assert updated["url"] == "old.url"

def test_add_entry_without_optional_fields(test_db, placeholder_key):
    entry_id = add_vault_entry(
        title="Minimal Entry",
        username=None,
        password="MinimalPass",
        url=None,
        notes=None,
        tags=None,
        key=placeholder_key,
        db_path=test_db
    )

    entry = get_vault_entry(entry_id, key=placeholder_key, db_path=test_db)
    assert entry["title"] == "Minimal Entry"
    assert entry["username"] is None
    assert entry["password"] == "MinimalPass"
    assert entry["url"] is None
    assert entry["notes"] is None
    assert entry["tags"] is None