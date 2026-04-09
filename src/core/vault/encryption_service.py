import json
import os
from typing import Dict, Any, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class EncryptionService:
    def __init__(self, key_manager):
        self.key_manager = key_manager

    def _get_cipher(self):
        key = self.key_manager.get_encryption_key()
        if not key:
            raise ValueError("Encryption key not available")
        return AESGCM(key)

    def encrypt_entry(self, entry: Dict[str, Any]) -> bytes:
        cipher = self._get_cipher()
        nonce = os.urandom(12)
        plaintext = json.dumps(entry).encode('utf-8')
        ciphertext = cipher.encrypt(nonce, plaintext, None)
        return nonce + ciphertext

    def decrypt_entry(self, encrypted_data: bytes) -> Optional[Dict[str, Any]]:
        if len(encrypted_data) < 28:
            return None

        cipher = self._get_cipher()
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]

        try:
            plaintext = cipher.decrypt(nonce, ciphertext, None)
            return json.loads(plaintext.decode('utf-8'))
        except Exception:
            return None