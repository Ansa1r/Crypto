import pytest
import secrets
from src.core.crypto.key_derivation import KeyDerivation


class TestKeyDerivationConsistencyDetailed:

    def setup_method(self):
        self.key_derivation = KeyDerivation()
        self.test_password = "TestPassword123!"
        self.test_salt = secrets.token_bytes(16)

    def test_derive_key_100_times_identical_detailed(self):
        first_key = self.key_derivation.derive_encryption_key(self.test_password, self.test_salt)

        for i in range(99):
            key = self.key_derivation.derive_encryption_key(self.test_password, self.test_salt)
            assert first_key == key

    def test_derive_key_1000_times_identical(self):
        keys = []

        for i in range(1000):
            key = self.key_derivation.derive_encryption_key(self.test_password, self.test_salt)
            keys.append(key)

        for i in range(1, 1000):
            assert keys[0] == keys[i]

    def test_derive_key_with_different_salts_all_different(self):
        salts = [secrets.token_bytes(16) for _ in range(50)]
        keys = []

        for salt in salts:
            key = self.key_derivation.derive_encryption_key(self.test_password, salt)
            keys.append(key)

        for i in range(len(keys)):
            for j in range(i + 1, len(keys)):
                assert keys[i] != keys[j]

    def test_derive_key_with_different_passwords_all_different(self):
        passwords = [f"Password{i}!" for i in range(50)]
        keys = []

        for pwd in passwords:
            key = self.key_derivation.derive_encryption_key(pwd, self.test_salt)
            keys.append(key)

        for i in range(len(keys)):
            for j in range(i + 1, len(keys)):
                assert keys[i] != keys[j]

    def test_hash_consistency_with_same_input_100_times(self):
        hashes = []
        salts = []

        for i in range(100):
            auth_hash, salt = self.key_derivation.create_auth_hash(self.test_password)
            hashes.append(auth_hash)
            salts.append(salt)

        for i in range(1, 100):
            assert hashes[0] != hashes[i]
            assert salts[0] != salts[i]

    def test_verify_password_consistency(self):
        auth_hash, salt = self.key_derivation.create_auth_hash(self.test_password)

        for i in range(100):
            is_valid = self.key_derivation.verify_password(self.test_password, auth_hash)
            assert is_valid is True

        for i in range(100):
            is_valid = self.key_derivation.verify_password("WrongPassword123!", auth_hash)
            assert is_valid is False

    def test_key_length_always_32(self):
        for i in range(100):
            salt = secrets.token_bytes(16)
            key = self.key_derivation.derive_encryption_key(self.test_password, salt)
            assert len(key) == 32

    def test_pbkdf2_iterations_change_produces_different_keys(self):
        configs = [
            {'pbkdf2_iterations': 100000},
            {'pbkdf2_iterations': 200000},
            {'pbkdf2_iterations': 300000},
            {'pbkdf2_iterations': 400000},
            {'pbkdf2_iterations': 500000},
            {'pbkdf2_iterations': 600000},
            {'pbkdf2_iterations': 700000},
            {'pbkdf2_iterations': 800000},
            {'pbkdf2_iterations': 900000},
            {'pbkdf2_iterations': 1000000}
        ]

        keys = []
        for config in configs:
            kd = KeyDerivation(config)
            key = kd.derive_encryption_key(self.test_password, self.test_salt)
            keys.append(key)

        for i in range(len(keys)):
            for j in range(i + 1, len(keys)):
                assert keys[i] != keys[j]