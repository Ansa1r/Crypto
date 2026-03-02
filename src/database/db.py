import sqlite3
from pathlib import Path
import shutil
from src.core.crypto.abstract import EncryptionService
from src.core.crypto.placeholder import AES256Placeholder

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DEFAULT_DB_PATH = BASE_DIR / "cryptosafe.db"
DB_PATH = DEFAULT_DB_PATH

def get_connection(db_path=DB_PATH):
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(db_path=DB_PATH):
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("PRAGMA foreign_keys = ON;")
    cursor.execute("PRAGMA user_version;")
    version = cursor.fetchone()[0]

    if version == 0:
        _create_initial_schema(cursor)
        cursor.execute("PRAGMA user_version = 1;")

    conn.commit()
    conn.close()

def _create_initial_schema(cursor):
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vault_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            username TEXT,
            encrypted_password BLOB NOT NULL,
            url TEXT,
            notes BLOB,
            tags TEXT,
            created_at TEXT,
            updated_at TEXT
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            entry_id INTEGER,
            details TEXT,
            signature BLOB
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            setting_key TEXT UNIQUE NOT NULL,
            setting_value BLOB,
            encrypted INTEGER NOT NULL DEFAULT 0
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS key_store (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_type TEXT NOT NULL,
            salt BLOB,
            hash BLOB,
            params TEXT
        );
    """)

def add_vault_entry(title, username, password, url, notes, tags, key=b'placeholder_key', db_path=DB_PATH):
    service = AES256Placeholder()
    encrypted_password = service.encrypt(password.encode(), key)
    encrypted_notes = service.encrypt(notes.encode(), key) if notes else None
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO vault_entries (title, username, encrypted_password, url, notes, tags, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
        """, (title, username, encrypted_password, url, encrypted_notes, tags))
        conn.commit()
        return cursor.lastrowid

def get_vault_entry(entry_id, key=b'placeholder_key', db_path=DB_PATH):
    service = AES256Placeholder()
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM vault_entries WHERE id = ?", (entry_id,))
        row = cursor.fetchone()
        if row:
            decrypted_password = service.decrypt(row['encrypted_password'], key).decode()
            decrypted_notes = service.decrypt(row['notes'], key).decode() if row['notes'] else None
            return {
                'id': row['id'],
                'title': row['title'],
                'username': row['username'],
                'password': decrypted_password,
                'url': row['url'],
                'notes': decrypted_notes,
                'tags': row['tags'],
                'created_at': row['created_at'],
                'updated_at': row['updated_at']
            }
        return None

def update_vault_entry(entry_id, title=None, username=None, password=None, url=None, notes=None, tags=None, key=b'placeholder_key', db_path=DB_PATH):
    service = AES256Placeholder()
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        updates = []
        params = []
        if title is not None:
            updates.append("title = ?")
            params.append(title)
        if username is not None:
            updates.append("username = ?")
            params.append(username)
        if password is not None:
            encrypted_password = service.encrypt(password.encode(), key)
            updates.append("encrypted_password = ?")
            params.append(encrypted_password)
        if url is not None:
            updates.append("url = ?")
            params.append(url)
        if notes is not None or 'notes' in locals():
            encrypted_notes = service.encrypt(notes.encode(), key) if notes else None
            updates.append("notes = ?")
            params.append(encrypted_notes)
        if tags is not None:
            updates.append("tags = ?")
            params.append(tags)
        if updates:
            updates.append("updated_at = datetime('now')")
            query = f"UPDATE vault_entries SET {', '.join(updates)} WHERE id = ?"
            params.append(entry_id)
            cursor.execute(query, params)
            conn.commit()

def backup_db(to_path, db_path=DB_PATH):
    shutil.copy(db_path, to_path)

def restore_db(from_path, db_path=DB_PATH):
    shutil.copy(from_path, db_path)