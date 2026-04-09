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

        encrypted_data = self.encryption_service.encrypt_entry(payload)

        with get_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO vault_entries (id, encrypted_data, created_at, updated_at)
                VALUES (?, ?, ?, ?)
            """, (entry_id, encrypted_data, now, now))
            conn.commit()

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

        encrypted_data = self.encryption_service.encrypt_entry(payload)

        with get_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE vault_entries 
                SET encrypted_data = ?, updated_at = ?
                WHERE id = ?
            """, (encrypted_data, now, entry_id))
            conn.commit()

        if self.event_bus:
            self.event_bus.publish('EntryUpdated', {'entry_id': entry_id, 'title': payload['title']})

        return True

    def delete_entry(self, entry_id: str, soft_delete: bool = True) -> bool:
        existing = self.get_entry(entry_id)
        if not existing:
            return False

        if soft_delete:
            now = datetime.now().isoformat()
            with get_connection(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO deleted_entries (id, original_id, title, deleted_data, deleted_at, expires_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    str(uuid.uuid4()),
                    entry_id,
                    existing.get('title', ''),
                    self.encryption_service.encrypt_entry(existing),
                    now,
                    (datetime.now().timestamp() + 2592000)
                ))
                cursor.execute("DELETE FROM vault_entries WHERE id = ?", (entry_id,))
                conn.commit()
        else:
            with get_connection(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM vault_entries WHERE id = ?", (entry_id,))
                conn.commit()

        if self.event_bus:
            self.event_bus.publish('EntryDeleted', {'entry_id': entry_id, 'title': existing.get('title', '')})

        return True

    def restore_entry(self, entry_id: str) -> bool:
        with get_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT original_id, deleted_data FROM deleted_entries WHERE original_id = ?", (entry_id,))
            row = cursor.fetchone()

            if not row:
                return False

            entry = self.encryption_service.decrypt_entry(row['deleted_data'])
            if not entry:
                return False

            now = datetime.now().isoformat()
            entry['updated_at'] = now

            encrypted_data = self.encryption_service.encrypt_entry(entry)

            cursor.execute("""
                INSERT INTO vault_entries (id, encrypted_data, created_at, updated_at)
                VALUES (?, ?, ?, ?)
            """, (entry_id, encrypted_data, entry.get('created_at', now), now))
            cursor.execute("DELETE FROM deleted_entries WHERE original_id = ?", (entry_id,))
            conn.commit()

        if self.event_bus:
            self.event_bus.publish('EntryRestored', {'entry_id': entry_id})

        return True

    def get_entry_count(self) -> int:
        with get_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM vault_entries")
            return cursor.fetchone()[0]