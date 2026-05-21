import json
import os
from typing import Dict, Any, Optional
from src.core.crypto.aes_gcm import AES256GCMEncryptionService


class EncryptionService:
    def __init__(self, key_manager):
        self.key_manager = key_manager
        self._aes_gcm_service = None

    def _get_service(self):
        if self._aes_gcm_service is None:
            self._aes_gcm_service = AES256GCMEncryptionService(self.key_manager)
        return self._aes_gcm_service

    def encrypt_entry(self, entry: Dict[str, Any]) -> bytes:
        service = self._get_service()
        plaintext = json.dumps(entry).encode('utf-8')
        return service.encrypt(plaintext)

    def decrypt_entry(self, encrypted_data: bytes) -> Optional[Dict[str, Any]]:
        if len(encrypted_data) < 28:
            return None
        service = self._get_service()
        try:
            plaintext = service.decrypt(encrypted_data)
            return json.loads(plaintext.decode('utf-8'))
        except Exception:
            return None