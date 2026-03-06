from .abstract import EncryptionService
from .secure_memory import secure_zero_bytes

class AES256Placeholder(EncryptionService):
    def encrypt(self, data: bytes, key: bytes) -> bytes:
        result = self._xor(data, key)
        secure_zero_bytes(key)
        return result

    def decrypt(self, ciphertext: bytes, key: bytes) -> bytes:
        result = self._xor(ciphertext, key)
        secure_zero_bytes(key)
        return result

    def _xor(self, data: bytes, key: bytes) -> bytes:
        result = bytearray()
        for i, b in enumerate(data):
            result.append(b ^ key[i % len(key)])
        secure_zero_bytes(key)
        return bytes(result)