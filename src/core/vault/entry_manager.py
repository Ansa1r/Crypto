import json
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any
from src.database.db import get_connection
from src.core.vault.encryption_service import EncryptionService
from src.core.events import EventBus


class EntryManager:
    def __init__(self, db_path: str, key_manager, event_bus: EventBus = None):
        self.db_path = db_path
        self.key_manager = key_manager
        self.event_bus = event_bus or EventBus()
        self.encryption_service = EncryptionService(key_manager)

    def create_entry(self, data: Dict[str, Any]) -> str:
        entry_id = str(uuid.uuid4())
        now = datetime.now().isoformat()

        payload = {
            'id': entry_id,
            'title': data.get('title', ''),
            'username': data.get('username', ''),
            'password': data.get('password', ''),
            'url': data.get('url', ''),
            'notes': data.get('notes', ''),
            'tags': data.get('tags', ''),
            'created_at': now,
            'updated_at': now,
            'version': 1
        }

        try:
            encrypted_data = self.encryption_service.encrypt_entry(payload)
        except Exception as e:
            raise ValueError(f"Encryption failed: {str(e)}")

        with get_connection(self.db_path) as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    INSERT INTO vault_entries (id, encrypted_data, created_at, updated_at)
                    VALUES (?, ?, ?, ?)
                """, (entry_id, encrypted_data, now, now))
                conn.commit()
            except Exception as e:
                conn.rollback()
                raise ValueError(f"Database error: {str(e)}")

        if self.event_bus:
            self.event_bus.publish('EntryCreated', {'entry_id': entry_id, 'title': data.get('title', '')})

        return entry_id

    def get_entry(self, entry_id: str) -> Optional[Dict[str, Any]]:
        with get_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT encrypted_data FROM vault_entries WHERE id = ?", (entry_id,))
            row = cursor.fetchone()

            if not row:
                return None

            encrypted_data = row['encrypted_data']
            return self.encryption_service.decrypt_entry(encrypted_data)

    def get_all_entries(self) -> List[Dict[str, Any]]:
        with get_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, encrypted_data, created_at, updated_at FROM vault_entries ORDER BY title")
            rows = cursor.fetchall()

            entries = []
            for row in rows:
                entry = self.encryption_service.decrypt_entry(row['encrypted_data'])
                if entry:
                    entries.append(entry)
            return entries

    def update_entry(self, entry_id: str, data: Dict[str, Any]) -> bool:
        existing = self.get_entry(entry_id)
        if not existing:
            return False

        now = datetime.now().isoformat()

        payload = {
            'id': entry_id,
            'title': data.get('title', existing.get('title', '')),
            'username': data.get('username', existing.get('username', '')),
            'password': data.get('password', existing.get('password', '')),
            'url': data.get('url', existing.get('url', '')),
            'notes': data.get('notes', existing.get('notes', '')),
            'tags': data.get('tags', existing.get('tags', '')),
            'created_at': existing.get('created_at', now),
            'updated_at': now,
            'version': existing.get('version', 1) + 1
        }

        try:
            encrypted_data = self.encryption_service.encrypt_entry(payload)
        except Exception as e:
            raise ValueError(f"Encryption failed: {str(e)}")

        with get_connection(self.db_path) as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    UPDATE vault_entries 
                    SET encrypted_data = ?, updated_at = ?
                    WHERE id = ?
                """, (encrypted_data, now, entry_id))
                if cursor.rowcount == 0:
                    conn.rollback()
                    return False
                conn.commit()
            except Exception as e:
                conn.rollback()
                raise ValueError(f"Database error: {str(e)}")

        if self.event_bus:
            self.event_bus.publish('EntryUpdated', {'entry_id': entry_id, 'title': payload['title']})

        return True

    def delete_entry(self, entry_id: str, soft_delete: bool = True) -> bool:
        existing = self.get_entry(entry_id)
        if not existing:
            return False

        with get_connection(self.db_path) as conn:
            cursor = conn.cursor()
            try:
                if soft_delete:
                    now = datetime.now().isoformat()
                    deleted_id = str(uuid.uuid4())
                    try:
                        encrypted_existing = self.encryption_service.encrypt_entry(existing)
                    except Exception as e:
                        conn.rollback()
                        raise ValueError(f"Encryption failed for soft delete: {str(e)}")

                    cursor.execute("""
                        INSERT INTO deleted_entries (id, original_id, title, deleted_data, deleted_at, expires_at)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (
                        deleted_id,
                        entry_id,
                        existing.get('title', ''),
                        encrypted_existing,
                        now,
                        datetime.now().timestamp() + 2592000
                    ))
                    cursor.execute("DELETE FROM vault_entries WHERE id = ?", (entry_id,))
                else:
                    cursor.execute("DELETE FROM vault_entries WHERE id = ?", (entry_id,))

                if cursor.rowcount == 0 and not soft_delete:
                    conn.rollback()
                    return False
                conn.commit()
            except Exception as e:
                conn.rollback()
                raise ValueError(f"Database error during delete: {str(e)}")

        if self.event_bus:
            self.event_bus.publish('EntryDeleted', {'entry_id': entry_id, 'title': existing.get('title', '')})

        return True

    def restore_entry(self, entry_id: str) -> bool:
        with get_connection(self.db_path) as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT original_id, deleted_data FROM deleted_entries WHERE original_id = ?",
                               (entry_id,))
                row = cursor.fetchone()

                if not row:
                    return False

                entry = self.encryption_service.decrypt_entry(row['deleted_data'])
                if not entry:
                    conn.rollback()
                    return False

                now = datetime.now().isoformat()
                entry['updated_at'] = now

                try:
                    encrypted_data = self.encryption_service.encrypt_entry(entry)
                except Exception as e:
                    conn.rollback()
                    raise ValueError(f"Encryption failed during restore: {str(e)}")

                cursor.execute("""
                    INSERT INTO vault_entries (id, encrypted_data, created_at, updated_at)
                    VALUES (?, ?, ?, ?)
                """, (entry_id, encrypted_data, entry.get('created_at', now), now))
                cursor.execute("DELETE FROM deleted_entries WHERE original_id = ?", (entry_id,))
                conn.commit()
            except Exception as e:
                conn.rollback()
                raise ValueError(f"Database error during restore: {str(e)}")

        if self.event_bus:
            self.event_bus.publish('EntryRestored', {'entry_id': entry_id})

        return True

    def delete_multiple_entries(self, entry_ids: List[str], soft_delete: bool = True) -> Dict[str, Any]:
        success_count = 0
        failed_ids = []

        with get_connection(self.db_path) as conn:
            cursor = conn.cursor()
            try:
                for entry_id in entry_ids:
                    existing = self.get_entry(entry_id)
                    if not existing:
                        failed_ids.append(entry_id)
                        continue

                    if soft_delete:
                        now = datetime.now().isoformat()
                        deleted_id = str(uuid.uuid4())
                        try:
                            encrypted_existing = self.encryption_service.encrypt_entry(existing)
                        except Exception:
                            failed_ids.append(entry_id)
                            continue

                        cursor.execute("""
                            INSERT INTO deleted_entries (id, original_id, title, deleted_data, deleted_at, expires_at)
                            VALUES (?, ?, ?, ?, ?, ?)
                        """, (
                            deleted_id,
                            entry_id,
                            existing.get('title', ''),
                            encrypted_existing,
                            now,
                            datetime.now().timestamp() + 2592000
                        ))
                        cursor.execute("DELETE FROM vault_entries WHERE id = ?", (entry_id,))
                    else:
                        cursor.execute("DELETE FROM vault_entries WHERE id = ?", (entry_id,))

                    if cursor.rowcount > 0 or soft_delete:
                        success_count += 1
                        if self.event_bus:
                            self.event_bus.publish('EntryDeleted',
                                                   {'entry_id': entry_id, 'title': existing.get('title', '')})
                    else:
                        failed_ids.append(entry_id)

                conn.commit()
            except Exception as e:
                conn.rollback()
                raise ValueError(f"Database error during batch delete: {str(e)}")

        return {
            'success_count': success_count,
            'failed_ids': failed_ids,
            'total': len(entry_ids)
        }

    def create_multiple_entries(self, entries_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        success_count = 0
        failed_entries = []

        with get_connection(self.db_path) as conn:
            cursor = conn.cursor()
            try:
                for data in entries_data:
                    entry_id = str(uuid.uuid4())
                    now = datetime.now().isoformat()

                    payload = {
                        'id': entry_id,
                        'title': data.get('title', ''),
                        'username': data.get('username', ''),
                        'password': data.get('password', ''),
                        'url': data.get('url', ''),
                        'notes': data.get('notes', ''),
                        'tags': data.get('tags', ''),
                        'created_at': now,
                        'updated_at': now,
                        'version': 1
                    }

                    try:
                        encrypted_data = self.encryption_service.encrypt_entry(payload)
                    except Exception:
                        failed_entries.append({'title': data.get('title', 'Unknown'), 'error': 'Encryption failed'})
                        continue

                    cursor.execute("""
                        INSERT INTO vault_entries (id, encrypted_data, created_at, updated_at)
                        VALUES (?, ?, ?, ?)
                    """, (entry_id, encrypted_data, now, now))

                    success_count += 1
                    if self.event_bus:
                        self.event_bus.publish('EntryCreated', {'entry_id': entry_id, 'title': data.get('title', '')})

                conn.commit()
            except Exception as e:
                conn.rollback()
                raise ValueError(f"Database error during batch create: {str(e)}")

        return {
            'success_count': success_count,
            'failed_entries': failed_entries,
            'total': len(entries_data)
        }

    def update_multiple_entries(self, updates: List[Dict[str, Any]]) -> Dict[str, Any]:
        success_count = 0
        failed_updates = []

        with get_connection(self.db_path) as conn:
            cursor = conn.cursor()
            try:
                for update_data in updates:
                    entry_id = update_data.get('id')
                    if not entry_id:
                        failed_updates.append({'id': None, 'error': 'No entry ID provided'})
                        continue

                    existing = self.get_entry(entry_id)
                    if not existing:
                        failed_updates.append({'id': entry_id, 'error': 'Entry not found'})
                        continue

                    now = datetime.now().isoformat()

                    payload = {
                        'id': entry_id,
                        'title': update_data.get('title', existing.get('title', '')),
                        'username': update_data.get('username', existing.get('username', '')),
                        'password': update_data.get('password', existing.get('password', '')),
                        'url': update_data.get('url', existing.get('url', '')),
                        'notes': update_data.get('notes', existing.get('notes', '')),
                        'tags': update_data.get('tags', existing.get('tags', '')),
                        'created_at': existing.get('created_at', now),
                        'updated_at': now,
                        'version': existing.get('version', 1) + 1
                    }

                    try:
                        encrypted_data = self.encryption_service.encrypt_entry(payload)
                    except Exception as e:
                        failed_updates.append({'id': entry_id, 'error': f'Encryption failed: {str(e)}'})
                        continue

                    cursor.execute("""
                        UPDATE vault_entries 
                        SET encrypted_data = ?, updated_at = ?
                        WHERE id = ?
                    """, (encrypted_data, now, entry_id))

                    if cursor.rowcount > 0:
                        success_count += 1
                        if self.event_bus:
                            self.event_bus.publish('EntryUpdated', {'entry_id': entry_id, 'title': payload['title']})
                    else:
                        failed_updates.append({'id': entry_id, 'error': 'Update failed'})

                conn.commit()
            except Exception as e:
                conn.rollback()
                raise ValueError(f"Database error during batch update: {str(e)}")

        return {
            'success_count': success_count,
            'failed_updates': failed_updates,
            'total': len(updates)
        }

    def get_entry_count(self) -> int:
        with get_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM vault_entries")
            result = cursor.fetchone()
            return result[0] if result else 0

    def entry_exists(self, entry_id: str) -> bool:
        with get_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM vault_entries WHERE id = ? LIMIT 1", (entry_id,))
            return cursor.fetchone() is not None

    def get_deleted_entries(self, limit: int = 100) -> List[Dict[str, Any]]:
        with get_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, original_id, title, deleted_at, expires_at 
                FROM deleted_entries 
                ORDER BY deleted_at DESC 
                LIMIT ?
            """, (limit,))
            rows = cursor.fetchall()

            deleted_entries = []
            for row in rows:
                deleted_entries.append({
                    'id': row['id'],
                    'original_id': row['original_id'],
                    'title': row['title'],
                    'deleted_at': row['deleted_at'],
                    'expires_at': row['expires_at']
                })
            return deleted_entries

    def permanently_delete_expired(self) -> int:
        with get_connection(self.db_path) as conn:
            cursor = conn.cursor()
            try:
                current_time = datetime.now().timestamp()
                cursor.execute("DELETE FROM deleted_entries WHERE expires_at < ?", (current_time,))
                deleted_count = cursor.rowcount
                conn.commit()
                return deleted_count
            except Exception as e:
                conn.rollback()
                raise ValueError(f"Database error during cleanup: {str(e)}")