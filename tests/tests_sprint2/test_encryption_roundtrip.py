import pytest
from src.core.crypto.placeholder import AES256Placeholder
from src.core.key_manager import KeyManager


class TestEncryptionRoundtrip:

    def setup_method(self):
        self.key_manager = KeyManager()
        self.encryption_service = AES256Placeholder(self.key_manager)
        self.test_key = b"test_key_32_bytes_for_encryption_test_"

    def test_encrypt_decrypt_roundtrip(self):
        self.key_manager.key_storage.store_encryption_key(self.test_key, use_keychain=False)

        plaintext = b"Hello, CryptoSafe! This is a test message."

        ciphertext = self.encryption_service.encrypt(plaintext)
        decrypted = self.encryption_service.decrypt(ciphertext)

        assert decrypted == plaintext
        assert decrypted != ciphertext

    def test_encrypt_empty_data(self):
        self.key_manager.key_storage.store_encryption_key(self.test_key, use_keychain=False)

        plaintext = b""

        ciphertext = self.encryption_service.encrypt(plaintext)
        decrypted = self.encryption_service.decrypt(ciphertext)

        assert decrypted == plaintext

    def test_encrypt_large_data(self):
        self.key_manager.key_storage.store_encryption_key(self.test_key, use_keychain=False)

        plaintext = b"X" * 10000

        ciphertext = self.encryption_service.encrypt(plaintext)
        decrypted = self.encryption_service.decrypt(ciphertext)

        assert decrypted == plaintext

    def test_encrypt_without_key_raises_error(self):
        self.key_manager.key_storage.clear()

        with pytest.raises(ValueError):
            self.encryption_service.encrypt(b"test")

    def test_decrypt_without_key_raises_error(self):
        self.key_manager.key_storage.clear()

        with pytest.raises(ValueError):
            self.encryption_service.decrypt(b"test")

    def test_different_keys_produce_different_ciphertext(self):
        key1 = b"key1_32_bytes_for_testing_purpose__"
        key2 = b"key2_32_bytes_for_testing_purpose__"

        self.key_manager.key_storage.store_encryption_key(key1, use_keychain=False)
        ciphertext1 = self.encryption_service.encrypt(b"Secret message")

        self.key_manager.key_storage.store_encryption_key(key2, use_keychain=False)
        ciphertext2 = self.encryption_service.encrypt(b"Secret message")

        assert ciphertext1 != ciphertext2