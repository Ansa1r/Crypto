from .abstract import EncryptionService

class AES256Placeholder(EncryptionService):
    def encrypt(self, data: bytes) -> bytes:
        key = self._get_key()
        return self._xor(data, key)

    def decrypt(self, data: bytes) -> bytes:
        key = self._get_key()
        return self._xor(data, key)

    def _xor(self, data: bytes, key: bytes) -> bytes:
        result = bytearray()
        key_len = len(key)
        for i, byte in enumerate(data):
            result.append(byte ^ key[i % key_len])
        return bytes(result)