import sqlite3
import pytest
from src.database.db import get_connection, DB_PATH

def test_database_file_created(temp_db):
    assert temp_db.exists()

def test_all_required(temp_db):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = {row["name"] for row in cursor.fetchall()}
    expected = {"vault_entries", "audit_log", "settings", "key_store"}
    assert expected.issubset(tables), f"Отсутствуют таблицы: {expected - tables}"
    conn.close()

def test_vault(temp_db):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(vault_entries);")
    columns = {row["name"] for row in cursor.fetchall()}
    expected = {
        "id", "title", "username", "encrypted_password",
        "url", "notes", "tags", "created_at", "updated_at"
    }
    assert expected.issubset(columns), f"Отсутствуют поля: {expected - columns}"
    conn.close()