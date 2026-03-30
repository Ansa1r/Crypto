import pytest
import time
import hashlib
import secrets
from src.core.crypto.key_derivation import KeyDerivation
from src.core.crypto.parameter_validator import ParameterValidator
from src.core.crypto.password_validator import PasswordValidator


class TestArgon2ParameterValidation:

    def setup_method(self):
        self.validator = ParameterValidator()
        self.key_derivation = KeyDerivation()

    def test_default_parameters_are_valid(self):
        params = self.key_derivation.get_current_params()

        is_valid, errors = self.validator.validate_argon2_params(
            params['argon2_time'],
            params['argon2_memory'],
            params['argon2_parallelism']
        )

        assert is_valid is True
        assert len(errors) == 0

    def test_minimum_parameters_are_valid(self):
        is_valid, errors = self.validator.validate_argon2_params(
            self.validator.min_argon2_time,
            self.validator.min_argon2_memory,
            self.validator.min_argon2_parallelism
        )

        assert is_valid is True
        assert len(errors) == 0

    def test_maximum_parameters_are_valid(self):
        is_valid, errors = self.validator.validate_argon2_params(
            self.validator.max_argon2_time,
            self.validator.max_argon2_memory,
            self.validator.max_argon2_parallelism
        )

        assert is_valid is True
        assert len(errors) == 0

    def test_invalid_time_cost_below_minimum(self):
        is_valid, errors = self.validator.validate_argon2_params(
            self.validator.min_argon2_time - 1,
            65536,
            4
        )

        assert is_valid is False
        assert len(errors) >= 1
        assert "cannot be less than" in errors[0]

    def test_invalid_time_cost_above_maximum(self):
        is_valid, errors = self.validator.validate_argon2_params(
            self.validator.max_argon2_time + 1,
            65536,
            4
        )

        assert is_valid is False
        assert len(errors) >= 1
        assert "cannot exceed" in errors[0]

    def test_invalid_memory_cost_below_minimum(self):
        is_valid, errors = self.validator.validate_argon2_params(
            3,
            self.validator.min_argon2_memory - 1024,
            4
        )

        assert is_valid is False
        assert len(errors) >= 1
        assert "cannot be less than" in errors[0]

    def test_invalid_memory_cost_above_maximum(self):
        is_valid, errors = self.validator.validate_argon2_params(
            3,
            self.validator.max_argon2_memory + 65536,
            4
        )

        assert is_valid is False
        assert len(errors) >= 1
        assert "cannot exceed" in errors[0]

    def test_invalid_parallelism_below_minimum(self):
        is_valid, errors = self.validator.validate_argon2_params(
            3,
            65536,
            self.validator.min_argon2_parallelism - 1
        )

        assert is_valid is False
        assert len(errors) >= 1
        assert "cannot be less than" in errors[0]

    def test_invalid_parallelism_above_maximum(self):
        is_valid, errors = self.validator.validate_argon2_params(
            3,
            65536,
            self.validator.max_argon2_parallelism + 1
        )

        assert is_valid is False
        assert len(errors) >= 1
        assert "cannot exceed" in errors[0]

    def test_parallelism_exceeds_memory_cost(self):
        memory_cost = 16384
        parallelism = 32

        is_valid, errors = self.validator.validate_argon2_params(3, memory_cost, parallelism)

        assert is_valid is False
        assert any("parallelism cannot exceed" in e for e in errors)

    def test_sanitize_parameters(self):
        time_cost, memory_cost, parallelism = self.validator.sanitize_argon2_params(
            -10,
            1024,
            100
        )

        assert time_cost == self.validator.min_argon2_time
        assert memory_cost == self.validator.min_argon2_memory
        assert parallelism == self.validator.max_argon2_parallelism


class TestKeyDerivationConsistency:

    def setup_method(self):
        self.key_derivation = KeyDerivation()
        self.test_password = "TestPassword123!"
        self.test_salt = secrets.token_bytes(16)

    def test_derive_key_100_times_identical(self):
        derived_keys = []

        for i in range(100):
            key = self.key_derivation.derive_encryption_key(self.test_password, self.test_salt)
            derived_keys.append(key)

        for i in range(1, 100):
            assert derived_keys[0] == derived_keys[i]

    def test_derive_key_consistent_with_different_instances(self):
        key1 = self.key_derivation.derive_encryption_key(self.test_password, self.test_salt)

        another_derivation = KeyDerivation()
        key2 = another_derivation.derive_encryption_key(self.test_password, self.test_salt)

        assert key1 == key2

    def test_derive_key_with_different_passwords(self):
        key1 = self.key_derivation.derive_encryption_key(self.test_password, self.test_salt)
        key2 = self.key_derivation.derive_encryption_key("DifferentPassword123!", self.test_salt)

        assert key1 != key2

    def test_derive_key_with_different_salts(self):
        salt1 = secrets.token_bytes(16)
        salt2 = secrets.token_bytes(16)

        key1 = self.key_derivation.derive_encryption_key(self.test_password, salt1)
        key2 = self.key_derivation.derive_encryption_key(self.test_password, salt2)

        assert key1 != key2

    def test_key_length_is_32_bytes(self):
        key = self.key_derivation.derive_encryption_key(self.test_password, self.test_salt)

        assert len(key) == 32

    def test_hash_consistency_with_same_input(self):
        hash1, salt1 = self.key_derivation.create_auth_hash(self.test_password)
        hash2, salt2 = self.key_derivation.create_auth_hash(self.test_password)

        assert hash1 != hash2
        assert salt1 != salt2

    def test_pbkdf2_iterations_affect_key(self):
        config1 = {'pbkdf2_iterations': 100000}
        config2 = {'pbkdf2_iterations': 200000}

        kd1 = KeyDerivation(config1)
        kd2 = KeyDerivation(config2)

        key1 = kd1.derive_encryption_key(self.test_password, self.test_salt)
        key2 = kd2.derive_encryption_key(self.test_password, self.test_salt)

        assert key1 != key2