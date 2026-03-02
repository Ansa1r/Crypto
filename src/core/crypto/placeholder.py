from .abstract import EncryptionService


class AES256Placeholder(EncryptionService):

    def encrypt(self, data: bytes, key: bytes) -> bytes:
        return self._xor(data, key)

    def decrypt(self, ciphertext: bytes, key: bytes) -> bytes:
        return self._xor(ciphertext, key)

    def _xor(self, data: bytes, key: bytes) -> bytes:
        result = bytearray()
        for i, b in enumerate(data):
            result.append(b ^ key[i % len(key)])
        return bytes(result)
