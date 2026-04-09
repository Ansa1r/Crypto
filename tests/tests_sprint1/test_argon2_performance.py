import pytest
import time
import gc
from src.core.crypto.key_derivation import KeyDerivation


class TestArgon2Performance:

    def setup_method(self):
        gc.collect()
        self.test_password = "TestPassword123!"

    def test_derivation_time_with_default_params(self):
        key_derivation = KeyDerivation()

        start = time.perf_counter()
        auth_hash, salt = key_derivation.create_auth_hash(self.test_password)
        derivation_time = time.perf_counter() - start

        assert derivation_time < 1.0
        assert auth_hash is not None

    def test_derivation_time_with_low_params(self):
        config = {
            'argon2_time': 1,
            'argon2_memory': 8192,
            'argon2_parallelism': 1,
            'pbkdf2_iterations': 100000
        }
        key_derivation = KeyDerivation(config)

        start = time.perf_counter()
        auth_hash, salt = key_derivation.create_auth_hash(self.test_password)
        derivation_time = time.perf_counter() - start

        assert derivation_time < 0.5
        assert auth_hash is not None

    def test_derivation_time_with_medium_params(self):
        config = {
            'argon2_time': 3,
            'argon2_memory': 32768,
            'argon2_parallelism': 2,
            'pbkdf2_iterations': 300000
        }
        key_derivation = KeyDerivation(config)

        start = time.perf_counter()
        auth_hash, salt = key_derivation.create_auth_hash(self.test_password)
        derivation_time = time.perf_counter() - start

        assert derivation_time < 1.5
        assert auth_hash is not None

    def test_multiple_derivations_consistent(self):
        key_derivation = KeyDerivation()
        times = []

        for _ in range(10):
            start = time.perf_counter()
            auth_hash, salt = key_derivation.create_auth_hash(self.test_password)
            times.append(time.perf_counter() - start)

        avg_time = sum(times) / len(times)
        max_time = max(times)

        assert max_time < avg_time * 2
        assert avg_time < 1.0

    def test_memory_usage_not_excessive(self):
        import tracemalloc

        tracemalloc.start()

        key_derivation = KeyDerivation()
        auth_hash, salt = key_derivation.create_auth_hash(self.test_password)

        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        assert peak < 100 * 1024 * 1024

    def test_verification_time_consistent(self):
        key_derivation = KeyDerivation()
        auth_hash, salt = key_derivation.create_auth_hash(self.test_password)

        correct_times = []

        for _ in range(10):
            start = time.perf_counter()
            key_derivation.verify_password(self.test_password, auth_hash)
            correct_times.append(time.perf_counter() - start)

        avg_correct = sum(correct_times) / len(correct_times)

        assert avg_correct < 0.5


class TestArgon2ParameterCombinations:

    def setup_method(self):
        self.test_password = "TestPassword123!"

    def test_low_time_high_memory(self):
        config = {
            'argon2_time': 1,
            'argon2_memory': 262144,
            'argon2_parallelism': 4,
            'pbkdf2_iterations': 600000
        }
        key_derivation = KeyDerivation(config)

        auth_hash, salt = key_derivation.create_auth_hash(self.test_password)

        assert auth_hash is not None
        assert "$argon2id$" in auth_hash

    def test_high_time_low_memory(self):
        config = {
            'argon2_time': 8,
            'argon2_memory': 16384,
            'argon2_parallelism': 2,
            'pbkdf2_iterations': 600000
        }
        key_derivation = KeyDerivation(config)

        auth_hash, salt = key_derivation.create_auth_hash(self.test_password)

        assert auth_hash is not None
        assert "$argon2id$" in auth_hash

    def test_high_parallelism(self):
        config = {
            'argon2_time': 2,
            'argon2_memory': 65536,
            'argon2_parallelism': 8,
            'pbkdf2_iterations': 600000
        }
        key_derivation = KeyDerivation(config)

        auth_hash, salt = key_derivation.create_auth_hash(self.test_password)

        assert auth_hash is not None
        assert "$argon2id$" in auth_hash

    def test_extreme_pbkdf2_iterations(self):
        config = {
            'argon2_time': 2,
            'argon2_memory': 65536,
            'argon2_parallelism': 4,
            'pbkdf2_iterations': 1000000
        }
        key_derivation = KeyDerivation(config)

        start = time.perf_counter()
        auth_hash, salt = key_derivation.create_auth_hash(self.test_password)
        derivation_time = time.perf_counter() - start

        assert auth_hash is not None
        assert derivation_time < 2.0