import sqlite3
from pathlib import Path
import shutil
from datetime import datetime
import json
import uuid

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DEFAULT_DB_PATH = BASE_DIR / "cryptosafe.db"
DB_PATH = DEFAULT_DB_PATH
DB_VERSION = 6


def get_connection(db_path=DB_PATH):
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path=DB_PATH):
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("PRAGMA foreign_keys = ON;")

    _create_tables(cursor)

    cursor.execute("PRAGMA user_version = {}".format(DB_VERSION))
    _initialize_default_settings(cursor)

    conn.commit()
    conn.close()


def _create_tables(cursor):
    cursor.execute("DROP TABLE IF EXISTS vault_entries")
    cursor.execute("DROP TABLE IF EXISTS deleted_entries")
    cursor.execute("DROP TABLE IF EXISTS audit_log")
    cursor.execute("DROP TABLE IF EXISTS settings")
    cursor.execute("DROP TABLE IF EXISTS key_store")

    cursor.execute("""
        CREATE TABLE vault_entries (
            id TEXT PRIMARY KEY,
            encrypted_data BLOB NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE deleted_entries (
            id TEXT PRIMARY KEY,
            original_id TEXT NOT NULL,
            title TEXT NOT NULL,
            deleted_data BLOB NOT NULL,
            deleted_at TEXT NOT NULL,
            expires_at REAL NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            entry_id TEXT,
            details TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            setting_key TEXT UNIQUE NOT NULL,
            setting_value TEXT,
            setting_type TEXT DEFAULT 'string',
            updated_at TEXT,
            description TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE key_store (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_type TEXT NOT NULL,
            key_data BLOB NOT NULL,
            version INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            params TEXT
        )
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_vault_entries_created_at ON vault_entries(created_at)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_vault_entries_updated_at ON vault_entries(updated_at)")


def _initialize_default_settings(cursor):
    default_settings = [
        ('password_min_length', '12', 'integer', datetime.now().isoformat(), 'Minimum length for master password'),
        ('password_require_uppercase', 'true', 'boolean', datetime.now().isoformat(),
         'Require uppercase letters in password'),
        ('password_require_lowercase', 'true', 'boolean', datetime.now().isoformat(),
         'Require lowercase letters in password'),
        ('password_require_digits', 'true', 'boolean', datetime.now().isoformat(), 'Require digits in password'),
        ('password_require_symbols', 'true', 'boolean', datetime.now().isoformat(),
         'Require special characters in password'),
        ('password_check_common', 'true', 'boolean', datetime.now().isoformat(), 'Check against common passwords list'),
        ('argon2_time_cost', '3', 'integer', datetime.now().isoformat(), 'Argon2 time cost parameter'),
        ('argon2_memory_cost', '65536', 'integer', datetime.now().isoformat(), 'Argon2 memory cost in KB (64MB)'),
        ('argon2_parallelism', '4', 'integer', datetime.now().isoformat(), 'Argon2 parallelism parameter'),
        ('pbkdf2_iterations', '600000', 'integer', datetime.now().isoformat(), 'PBKDF2 iteration count'),
        ('auto_lock_timeout', '3600', 'integer', datetime.now().isoformat(), 'Auto-lock timeout in seconds'),
        ('clipboard_timeout', '15', 'integer', datetime.now().isoformat(), 'Clipboard clear timeout in seconds'),
        ('inactivity_lock', 'true', 'boolean', datetime.now().isoformat(), 'Lock vault on inactivity'),
        ('minimize_to_tray', 'false', 'boolean', datetime.now().isoformat(), 'Minimize to system tray'),
        ('theme', 'system', 'string', datetime.now().isoformat(), 'Application theme (light/dark/system)'),
        ('language', 'en', 'string', datetime.now().isoformat(), 'Application language'),
        ('backup_enabled', 'true', 'boolean', datetime.now().isoformat(), 'Enable automatic backups'),
        ('backup_interval', '86400', 'integer', datetime.now().isoformat(), 'Backup interval in seconds (24 hours)'),
        ('backup_retention_days', '30', 'integer', datetime.now().isoformat(), 'Number of days to keep backups'),
        ('keychain_enabled', 'true', 'boolean', datetime.now().isoformat(), 'Enable OS keychain integration'),
        ('fast_unlock_enabled', 'true', 'boolean', datetime.now().isoformat(), 'Enable fast unlock with cached key'),
        ('cache_ttl', '3600', 'integer', datetime.now().isoformat(), 'Key cache TTL in seconds'),
        ('audit_log_enabled', 'true', 'boolean', datetime.now().isoformat(), 'Enable audit logging'),
        ('audit_log_retention_days', '90', 'integer', datetime.now().isoformat(), 'Audit log retention in days')
    ]

    for key, value, value_type, updated_at, description in default_settings:
        cursor.execute("""
            INSERT OR IGNORE INTO settings (setting_key, setting_value, setting_type, updated_at, description)
            VALUES (?, ?, ?, ?, ?)
        """, (key, value, value_type, updated_at, description))


def get_setting(setting_key, db_path=DB_PATH):
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT setting_value, setting_type FROM settings WHERE setting_key = ?", (setting_key,))
        row = cursor.fetchone()

        if row:
            value = row['setting_value']
            value_type = row['setting_type']

            if value_type == 'integer':
                return int(value)
            elif value_type == 'boolean':
                return value.lower() == 'true'
            elif value_type == 'float':
                return float(value)
            elif value_type == 'json':
                return json.loads(value)
            else:
                return value

        return None


def set_setting(setting_key, setting_value, setting_type='string', description=None, db_path=DB_PATH):
    from src.core.crypto.parameter_validator import ParameterValidator

    validator = ParameterValidator()

    if setting_key == 'argon2_time_cost':
        try:
            is_valid, errors = validator.validate_argon2_params(int(setting_value), 65536, 4)
            if not is_valid:
                raise ValueError(f"Invalid Argon2 time cost: {', '.join(errors)}")
        except ValueError as e:
            raise e

    if setting_key == 'argon2_memory_cost':
        try:
            is_valid, errors = validator.validate_argon2_params(3, int(setting_value), 4)
            if not is_valid:
                raise ValueError(f"Invalid Argon2 memory cost: {', '.join(errors)}")
        except ValueError as e:
            raise e

    if setting_key == 'argon2_parallelism':
        try:
            is_valid, errors = validator.validate_argon2_params(3, 65536, int(setting_value))
            if not is_valid:
                raise ValueError(f"Invalid Argon2 parallelism: {', '.join(errors)}")
        except ValueError as e:
            raise e

    if setting_key == 'pbkdf2_iterations':
        try:
            is_valid, errors = validator.validate_pbkdf2_params(int(setting_value))
            if not is_valid:
                raise ValueError(f"Invalid PBKDF2 iterations: {', '.join(errors)}")
        except ValueError as e:
            raise e

    with get_connection(db_path) as conn:
        cursor = conn.cursor()

        if isinstance(setting_value, bool):
            setting_value = str(setting_value).lower()
            setting_type = 'boolean'
        elif isinstance(setting_value, int):
            setting_value = str(setting_value)
            setting_type = 'integer'
        elif isinstance(setting_value, float):
            setting_value = str(setting_value)
            setting_type = 'float'
        elif isinstance(setting_value, (dict, list)):
            setting_value = json.dumps(setting_value)
            setting_type = 'json'

        cursor.execute("""
            INSERT INTO settings (setting_key, setting_value, setting_type, updated_at, description)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(setting_key) DO UPDATE SET
                setting_value = excluded.setting_value,
                setting_type = excluded.setting_type,
                updated_at = excluded.updated_at,
                description = COALESCE(excluded.description, description)
        """, (setting_key, setting_value, setting_type, datetime.now().isoformat(), description))

        conn.commit()
        return True


def get_all_settings(db_path=DB_PATH):
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT setting_key, setting_value, setting_type, description FROM settings ORDER BY setting_key")
        rows = cursor.fetchall()

        settings = {}
        for row in rows:
            key = row['setting_key']
            value = row['setting_value']
            value_type = row['setting_type']

            if value_type == 'integer':
                settings[key] = int(value)
            elif value_type == 'boolean':
                settings[key] = value.lower() == 'true'
            elif value_type == 'float':
                settings[key] = float(value)
            elif value_type == 'json':
                settings[key] = json.loads(value)
            else:
                settings[key] = value

        return settings


def update_settings(settings_dict, db_path=DB_PATH):
    from src.core.crypto.parameter_validator import ParameterValidator

    validator = ParameterValidator()

    argon2_time = settings_dict.get('argon2_time_cost', 3)
    argon2_memory = settings_dict.get('argon2_memory_cost', 65536)
    argon2_parallelism = settings_dict.get('argon2_parallelism', 4)
    pbkdf2_iterations = settings_dict.get('pbkdf2_iterations', 600000)

    is_valid, errors = validator.validate_combined_params(
        argon2_time, argon2_memory, argon2_parallelism, pbkdf2_iterations
    )

    if not is_valid:
        raise ValueError(f"Invalid parameters: {', '.join(errors)}")

    with get_connection(db_path) as conn:
        cursor = conn.cursor()

        for key, value in settings_dict.items():
            if isinstance(value, bool):
                value_str = str(value).lower()
                value_type = 'boolean'
            elif isinstance(value, int):
                value_str = str(value)
                value_type = 'integer'
            elif isinstance(value, float):
                value_str = str(value)
                value_type = 'float'
            elif isinstance(value, (dict, list)):
                value_str = json.dumps(value)
                value_type = 'json'
            else:
                value_str = str(value)
                value_type = 'string'

            cursor.execute("""
                INSERT INTO settings (setting_key, setting_value, setting_type, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(setting_key) DO UPDATE SET
                    setting_value = excluded.setting_value,
                    setting_type = excluded.setting_type,
                    updated_at = excluded.updated_at
            """, (key, value_str, value_type, datetime.now().isoformat()))

        conn.commit()
        return True


def get_key_derivation_params(db_path=DB_PATH):
    params = {
        'argon2_time': get_setting('argon2_time_cost', db_path) or 3,
        'argon2_memory': get_setting('argon2_memory_cost', db_path) or 65536,
        'argon2_parallelism': get_setting('argon2_parallelism', db_path) or 4,
        'pbkdf2_iterations': get_setting('pbkdf2_iterations', db_path) or 600000
    }
    return params


def get_password_policy(db_path=DB_PATH):
    policy = {
        'min_length': get_setting('password_min_length', db_path) or 12,
        'require_uppercase': get_setting('password_require_uppercase', db_path) or True,
        'require_lowercase': get_setting('password_require_lowercase', db_path) or True,
        'require_digits': get_setting('password_require_digits', db_path) or True,
        'require_symbols': get_setting('password_require_symbols', db_path) or True,
        'check_common': get_setting('password_check_common', db_path) or True
    }
    return policy


def get_security_settings(db_path=DB_PATH):
    settings = {
        'auto_lock_timeout': get_setting('auto_lock_timeout', db_path) or 3600,
        'clipboard_timeout': get_setting('clipboard_timeout', db_path) or 15,
        'inactivity_lock': get_setting('inactivity_lock', db_path) or True,
        'keychain_enabled': get_setting('keychain_enabled', db_path) or True,
        'fast_unlock_enabled': get_setting('fast_unlock_enabled', db_path) or True,
        'cache_ttl': get_setting('cache_ttl', db_path) or 3600
    }
    return settings


def get_backup_settings(db_path=DB_PATH):
    settings = {
        'backup_enabled': get_setting('backup_enabled', db_path) or True,
        'backup_interval': get_setting('backup_interval', db_path) or 86400,
        'backup_retention_days': get_setting('backup_retention_days', db_path) or 30
    }
    return settings


def get_audit_settings(db_path=DB_PATH):
    settings = {
        'audit_log_enabled': get_setting('audit_log_enabled', db_path) or True,
        'audit_log_retention_days': get_setting('audit_log_retention_days', db_path) or 90
    }
    return settings


def set_master_password(password, db_path=DB_PATH):
    from src.core.crypto.key_derivation import KeyDerivation

    kd = KeyDerivation()

    auth_hash, pbkdf2_salt = kd.create_auth_hash(password)

    with get_connection(db_path) as conn:
        cursor = conn.cursor()

        cursor.execute("DELETE FROM key_store WHERE key_type IN ('auth_hash', 'pbkdf2_salt')")

        cursor.execute("""
            INSERT INTO key_store (key_type, key_data, params)
            VALUES (?, ?, ?)
        """, ('auth_hash', auth_hash.encode('utf-8'),
              json.dumps({'algorithm': 'argon2id', 'version': 1})))

        cursor.execute("""
            INSERT INTO key_store (key_type, key_data, params)
            VALUES (?, ?, ?)
        """, ('pbkdf2_salt', pbkdf2_salt,
              json.dumps({'algorithm': 'pbkdf2', 'iterations': 600000, 'version': 1})))

        conn.commit()


def verify_master_password(password, db_path=DB_PATH):
    from src.core.crypto.key_derivation import KeyDerivation

    kd = KeyDerivation()

    with get_connection(db_path) as conn:
        cursor = conn.cursor()

        cursor.execute("""
            SELECT key_data FROM key_store 
            WHERE key_type = 'auth_hash' 
            ORDER BY created_at DESC LIMIT 1
        """)
        row = cursor.fetchone()

        if not row:
            return False

        stored_hash = row['key_data'].decode('utf-8')
        return kd.verify_password(password, stored_hash)


def get_pbkdf2_salt(db_path=DB_PATH):
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT key_data FROM key_store 
            WHERE key_type = 'pbkdf2_salt' 
            ORDER BY created_at DESC LIMIT 1
        """)
        row = cursor.fetchone()
        return row['key_data'] if row else None


def has_master_password(db_path=DB_PATH):
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM key_store WHERE key_type = 'auth_hash'")
        count = cursor.fetchone()[0]
        return count > 0


def add_vault_entry(title, username, password, url, notes, tags, db_path=DB_PATH):
    from src.core.key_manager import KeyManager
    from src.core.vault.encryption_service import EncryptionService

    key_manager = KeyManager()
    encryption_service = EncryptionService(key_manager)

    entry_id = str(uuid.uuid4())
    now = datetime.now().isoformat()

    payload = {
        'id': entry_id,
        'title': title,
        'username': username or '',
        'password': password,
        'url': url or '',
        'notes': notes or '',
        'tags': tags or '',
        'created_at': now,
        'updated_at': now,
        'version': 1
    }

    encrypted_data = encryption_service.encrypt_entry(payload)

    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO vault_entries (id, encrypted_data, created_at, updated_at)
            VALUES (?, ?, ?, ?)
        """, (entry_id, encrypted_data, now, now))
        conn.commit()

    return entry_id


def get_vault_entry(entry_id, db_path=DB_PATH):
    from src.core.key_manager import KeyManager
    from src.core.vault.encryption_service import EncryptionService

    key_manager = KeyManager()
    encryption_service = EncryptionService(key_manager)

    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT encrypted_data, created_at, updated_at FROM vault_entries WHERE id = ?", (entry_id,))
        row = cursor.fetchone()

        if not row:
            return None

        encrypted_data = row['encrypted_data']
        return encryption_service.decrypt_entry(encrypted_data)


def get_all_vault_entries(db_path=DB_PATH):
    from src.core.key_manager import KeyManager
    from src.core.vault.encryption_service import EncryptionService

    key_manager = KeyManager()
    encryption_service = EncryptionService(key_manager)

    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, encrypted_data, created_at, updated_at FROM vault_entries")
        rows = cursor.fetchall()

        entries = []
        for row in rows:
            encrypted_data = row['encrypted_data']
            entry = encryption_service.decrypt_entry(encrypted_data)
            if entry:
                entries.append(entry)

        return entries


def update_vault_entry(entry_id, title=None, username=None, password=None, url=None, notes=None, tags=None,
                       db_path=DB_PATH):
    from src.core.key_manager import KeyManager
    from src.core.vault.encryption_service import EncryptionService

    key_manager = KeyManager()
    encryption_service = EncryptionService(key_manager)

    existing = get_vault_entry(entry_id, db_path)
    if not existing:
        return False

    now = datetime.now().isoformat()

    if title is not None:
        existing['title'] = title
    if username is not None:
        existing['username'] = username
    if password is not None:
        existing['password'] = password
    if url is not None:
        existing['url'] = url
    if notes is not None:
        existing['notes'] = notes
    if tags is not None:
        existing['tags'] = tags

    existing['updated_at'] = now
    existing['version'] = existing.get('version', 1) + 1

    encrypted_data = encryption_service.encrypt_entry(existing)

    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE vault_entries 
            SET encrypted_data = ?, updated_at = ?
            WHERE id = ?
        """, (encrypted_data, now, entry_id))
        conn.commit()

    return True


def delete_vault_entry(entry_id, db_path=DB_PATH):
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM vault_entries WHERE id = ?", (entry_id,))
        conn.commit()
        return cursor.rowcount > 0


def search_vault_entries(search_term, db_path=DB_PATH):
    entries = get_all_vault_entries(db_path)
    search_lower = search_term.lower()

    results = []
    for entry in entries:
        if (search_lower in entry.get('title', '').lower() or
                search_lower in entry.get('username', '').lower() or
                search_lower in entry.get('url', '').lower() or
                search_lower in entry.get('tags', '').lower() or
                search_lower in entry.get('notes', '').lower()):
            results.append(entry)

    return results


def add_audit_log(action, entry_id=None, details=None, db_path=DB_PATH):
    if not get_setting('audit_log_enabled', db_path):
        return None

    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO audit_log (action, timestamp, entry_id, details)
            VALUES (?, ?, ?, ?)
        """, (action, datetime.now().isoformat(), entry_id, details))
        conn.commit()

        retention_days = get_setting('audit_log_retention_days', db_path) or 90
        if retention_days > 0:
            cutoff_date = (datetime.now().timestamp() - retention_days * 86400)
            cursor.execute("""
                DELETE FROM audit_log WHERE strftime('%s', timestamp) < ?
            """, (cutoff_date,))
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


def get_db_version(db_path=DB_PATH):
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("PRAGMA user_version")
        return cursor.fetchone()[0]


def reset_settings_to_default(db_path=DB_PATH):
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM settings")
        _initialize_default_settings(cursor)
        conn.commit()
        return True


def export_settings(db_path=DB_PATH):
    settings = get_all_settings(db_path)
    return json.dumps(settings, indent=2)


def import_settings(settings_json, db_path=DB_PATH):
    try:
        settings = json.loads(settings_json)
        return update_settings(settings, db_path)
    except Exception:
        return False