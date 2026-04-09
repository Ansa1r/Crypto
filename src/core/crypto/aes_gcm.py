import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from src.core.crypto.abstract import EncryptionService


class AES256GCMEncryptionService(EncryptionService):
    def __init__(self, key_manager):
        super().__init__(key_manager)

    def _get_cipher(self):
        key = self.get_encryption_key()
        if not key:
            raise ValueError("Encryption key not available")
        return AESGCM(key)

    def encrypt(self, data: bytes) -> bytes:
        cipher = self._get_cipher()
        nonce = os.urandom(12)
        ciphertext = cipher.encrypt(nonce, data, None)
        return nonce + ciphertext

    def decrypt(self, encrypted_data: bytes) -> bytes:
        if len(encrypted_data) < 28:
            raise ValueError("Invalid encrypted data")

        cipher = self._get_cipher()
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]

        try:
            plaintext = cipher.decrypt(nonce, ciphertext, None)
            return plaintext
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")