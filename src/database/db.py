import sqlite3
from pathlib import Path
import shutil
from datetime import datetime
import hashlib
import secrets

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DEFAULT_DB_PATH = BASE_DIR / "cryptosafe.db"
DB_PATH = DEFAULT_DB_PATH
DB_VERSION = 2

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
            password TEXT NOT NULL,
            url TEXT,
            notes TEXT,
            tags TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            entry_id INTEGER,
            details TEXT
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            setting_key TEXT UNIQUE NOT NULL,
            setting_value TEXT
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


def migrate(db_path: Path):
    conn = get_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("PRAGMA user_version")
    current_version = cursor.fetchone()[0]

    if current_version < DB_VERSION:
        if current_version == 0:
            cursor.executescript("""
                CREATE TABLE IF NOT EXISTS vault_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    username TEXT,
                    encrypted_password BLOB,
                    url TEXT,
                    notes TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    tags TEXT
                );
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    entry_id INTEGER,
                    details TEXT,
                    signature BLOB
                );
                CREATE TABLE IF NOT EXISTS settings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    setting_key TEXT UNIQUE,
                    setting_value TEXT,
                    encrypted BOOLEAN DEFAULT 0
                );
            """)

        if current_version < 1:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS key_store (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key_type TEXT NOT NULL,
                    key_data BLOB,
                    version INTEGER DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

        if current_version < 2:
            cursor.execute("ALTER TABLE key_store ADD COLUMN params TEXT")

        conn.execute(f"PRAGMA user_version = {DB_VERSION}")
        conn.commit()

    conn.close()

def set_master_password(password, db_path=DB_PATH):
    salt = secrets.token_bytes(32)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)

    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM key_store WHERE key_type = 'master'")
        cursor.execute("""
            INSERT INTO key_store (key_type, salt, hash, params)
            VALUES (?, ?, ?, ?)
        """, ('master', salt, key, 'pbkdf2:sha256:100000'))
        conn.commit()


def verify_master_password(password, db_path=DB_PATH):
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT salt, hash FROM key_store WHERE key_type = 'master'")
        row = cursor.fetchone()

        if not row:
            return False

        salt = row['salt']
        stored_hash = row['hash']

        test_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)

        return secrets.compare_digest(test_hash, stored_hash)


def has_master_password(db_path=DB_PATH):
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM key_store WHERE key_type = 'master'")
        count = cursor.fetchone()[0]
        return count > 0


def add_vault_entry(title, username, password, url, notes, tags, db_path=DB_PATH):
    now = datetime.now().isoformat()
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO vault_entries (title, username, password, url, notes, tags, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (title, username, password, url, notes, tags, now, now))
        conn.commit()
        return cursor.lastrowid


def get_vault_entry(entry_id, db_path=DB_PATH):
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM vault_entries WHERE id = ?", (entry_id,))
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None


def get_all_vault_entries(db_path=DB_PATH):
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM vault_entries ORDER BY title")
        return [dict(row) for row in cursor.fetchall()]


def update_vault_entry(entry_id, title=None, username=None, password=None, url=None, notes=None, tags=None,
                       db_path=DB_PATH):
    with get_connection(db_path) as conn:
        cursor = conn.cursor()

        current = get_vault_entry(entry_id, db_path)
        if not current:
            return False

        updates = []
        params = []

        if title is not None:
            updates.append("title = ?")
            params.append(title)
        if username is not None:
            updates.append("username = ?")
            params.append(username)
        if password is not None:
            updates.append("password = ?")
            params.append(password)
        if url is not None:
            updates.append("url = ?")
            params.append(url)
        if notes is not None:
            updates.append("notes = ?")
            params.append(notes)
        if tags is not None:
            updates.append("tags = ?")
            params.append(tags)

        if updates:
            updates.append("updated_at = ?")
            params.append(datetime.now().isoformat())
            params.append(entry_id)

            query = f"UPDATE vault_entries SET {', '.join(updates)} WHERE id = ?"
            cursor.execute(query, params)
            conn.commit()
            return True
        return False


def delete_vault_entry(entry_id, db_path=DB_PATH):
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM vault_entries WHERE id = ?", (entry_id,))
        conn.commit()
        return cursor.rowcount > 0


def search_vault_entries(search_term, db_path=DB_PATH):
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM vault_entries 
            WHERE title LIKE ? OR username LIKE ? OR url LIKE ? OR tags LIKE ?
            ORDER BY title
        """, (f'%{search_term}%', f'%{search_term}%', f'%{search_term}%', f'%{search_term}%'))
        return [dict(row) for row in cursor.fetchall()]


def add_audit_log(action, entry_id=None, details=None, db_path=DB_PATH):
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO audit_log (action, timestamp, entry_id, details)
            VALUES (?, ?, ?, ?)
        """, (action, datetime.now().isoformat(), entry_id, details))
        conn.commit()
        return cursor.lastrowid


def get_audit_logs(limit=100, db_path=DB_PATH):
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM audit_log 
            ORDER BY timestamp DESC 
            LIMIT ?
        """, (limit,))
        return [dict(row) for row in cursor.fetchall()]


def backup_db(to_path, db_path=DB_PATH):
    shutil.copy(db_path, to_path)


def restore_db(from_path, db_path=DB_PATH):
    shutil.copy(from_path, db_path)