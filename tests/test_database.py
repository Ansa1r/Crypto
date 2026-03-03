import pytest
import os
from src.database.db import (
    init_db, add_vault_entry, get_vault_entry, get_all_vault_entries,
    update_vault_entry, delete_vault_entry, search_vault_entries,
    add_audit_log, get_audit_logs, get_connection
)


def test_init_db_creates_tables(test_db):
    with get_connection(db_path=test_db) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = {row[0] for row in cursor.fetchall()}
        expected = {"vault_entries", "audit_log", "settings", "key_store"}
        assert expected.issubset(tables)


def test_add_and_get_vault_entry(test_db):
    entry_id = add_vault_entry(
        title="Test Site",
        username="user123",
        password="SecretPass123",
        url="https://example.com",
        notes="Some important note",
        tags="work,important",
        db_path=test_db
    )
    assert entry_id > 0

    entry = get_vault_entry(entry_id, db_path=test_db)
    assert entry is not None
    assert entry["title"] == "Test Site"
    assert entry["username"] == "user123"
    assert entry["password"] == "SecretPass123"
    assert entry["url"] == "https://example.com"
    assert entry["notes"] == "Some important note"
    assert entry["tags"] == "work,important"


def test_get_all_vault_entries(test_db):
    add_vault_entry(title="Entry 1", username="user1", password="pass1", url=None, notes=None, tags=None,
                    db_path=test_db)
    add_vault_entry(title="Entry 2", username="user2", password="pass2", url=None, notes=None, tags=None,
                    db_path=test_db)

    entries = get_all_vault_entries(test_db)
    assert len(entries) == 2
    assert entries[0]["title"] == "Entry 1"
    assert entries[1]["title"] == "Entry 2"


def test_update_vault_entry(test_db):
    entry_id = add_vault_entry(
        title="Old Title",
        username="olduser",
        password="oldpass",
        url="old.url",
        notes="old note",
        tags="old",
        db_path=test_db
    )

    update_vault_entry(
        entry_id=entry_id,
        title="New Title",
        password="NewSuperPass456",
        notes=None,
        tags="new,updated",
        db_path=test_db
    )

    updated = get_vault_entry(entry_id, db_path=test_db)
    assert updated["title"] == "New Title"
    assert updated["password"] == "NewSuperPass456"
    assert updated["notes"] is None
    assert updated["tags"] == "new,updated"
    assert updated["username"] == "olduser"
    assert updated["url"] == "old.url"


def test_delete_vault_entry(test_db):
    entry_id = add_vault_entry(
        title="To Delete",
        username="delete_user",
        password="delete_pass",
        url=None,
        notes=None,
        tags=None,
        db_path=test_db
    )

    assert get_vault_entry(entry_id, db_path=test_db) is not None

    result = delete_vault_entry(entry_id, db_path=test_db)
    assert result is True

    assert get_vault_entry(entry_id, db_path=test_db) is None


def test_search_vault_entries(test_db):
    add_vault_entry(title="Google Account", username="user@gmail.com", password="pass1", url="google.com", notes=None,
                    tags="work", db_path=test_db)
    add_vault_entry(title="GitHub", username="dev", password="pass2", url="github.com", notes=None, tags="dev",
                    db_path=test_db)
    add_vault_entry(title="Bank of America", username="customer", password="pass3", url="bank.com", notes=None,
                    tags="finance", db_path=test_db)

    results = search_vault_entries("google", test_db)
    assert len(results) == 1
    assert results[0]["title"] == "Google Account"

    results = search_vault_entries("bank", test_db)
    assert len(results) == 1
    assert results[0]["title"] == "Bank of America"

    results = search_vault_entries("com", test_db)
    assert len(results) == 3


def test_audit_log(test_db):
    log_id = add_audit_log("TestAction", entry_id=1, details="Test details", db_path=test_db)
    assert log_id > 0

    entry_id = add_vault_entry(title="Test", username="user", password="pass", url=None, notes=None, tags=None,
                               db_path=test_db)
    add_audit_log("EntryAdded", entry_id, "Added test entry", db_path=test_db)

    logs = get_audit_logs(10, test_db)
    assert len(logs) >= 2

    found_test = False
    found_entry = False
    for log in logs:
        if log["action"] == "TestAction":
            found_test = True
        if log["action"] == "EntryAdded" and log["entry_id"] == entry_id:
            found_entry = True

    assert found_test
    assert found_entry


def test_add_entry_without_optional_fields(test_db):
    entry_id = add_vault_entry(
        title="Minimal Entry",
        username=None,
        password="MinimalPass",
        url=None,
        notes=None,
        tags=None,
        db_path=test_db
    )

    entry = get_vault_entry(entry_id, db_path=test_db)
    assert entry["title"] == "Minimal Entry"
    assert entry["username"] is None
    assert entry["password"] == "MinimalPass"
    assert entry["url"] is None
    assert entry["notes"] is None
    assert entry["tags"] is None