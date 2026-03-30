import pytest
import time
import statistics
from src.core.crypto.key_derivation import KeyDerivation
from src.core.crypto.authentication import AuthenticationService


class TestTimingAttackResistance:

    def setup_method(self):
        self.key_derivation = KeyDerivation()
        self.auth_service = AuthenticationService(self.key_derivation)
        self.test_password = "TestPassword123!"

    def test_password_verification_timing_consistency(self):
        auth_hash, _ = self.key_derivation.create_auth_hash(self.test_password)

        correct_times = []
        incorrect_times = []

        for _ in range(100):
            start = time.perf_counter()
            self.key_derivation.verify_password(self.test_password, auth_hash)
            correct_times.append(time.perf_counter() - start)

        for _ in range(100):
            start = time.perf_counter()
            self.key_derivation.verify_password("wrong_password", auth_hash)
            incorrect_times.append(time.perf_counter() - start)

        avg_correct = statistics.mean(correct_times)
        avg_incorrect = statistics.mean(incorrect_times)
        std_correct = statistics.stdev(correct_times) if len(correct_times) > 1 else 0
        std_incorrect = statistics.stdev(incorrect_times) if len(incorrect_times) > 1 else 0

        time_ratio = max(avg_correct, avg_incorrect) / min(avg_correct, avg_incorrect)

        assert time_ratio < 1.5

    def test_verify_with_varying_password_lengths(self):
        auth_hash, _ = self.key_derivation.create_auth_hash(self.test_password)

        passwords = [
            "a",
            "ab",
            "abc",
            "abcd",
            "abcde",
            "abcdef",
            "abcdefg",
            "abcdefgh",
            "abcdefghi",
            "abcdefghij"
        ]

        times = []
        for password in passwords:
            start = time.perf_counter()
            self.key_derivation.verify_password(password, auth_hash)
            times.append(time.perf_counter() - start)

        max_time = max(times)
        min_time = min(times)

        assert max_time - min_time < 0.01

    def test_verify_with_similar_passwords(self):
        auth_hash, _ = self.key_derivation.create_auth_hash(self.test_password)

        similar_passwords = [
            "TestPassword123!",
            "TestPassword123@",
            "TestPassword124!",
            "TestPassword122!",
            "TestPassword123",
            "testpassword123!",
            "TestPassword123!!",
            "TestPassword123!a"
        ]

        times = []
        for pwd in similar_passwords:
            start = time.perf_counter()
            self.key_derivation.verify_password(pwd, auth_hash)
            times.append(time.perf_counter() - start)

        max_time = max(times)
        min_time = min(times)

        assert max_time - min_time < 0.01

    def test_verify_with_empty_string(self):
        auth_hash, _ = self.key_derivation.create_auth_hash(self.test_password)

        empty_times = []

        for _ in range(50):
            start = time.perf_counter()
            self.key_derivation.verify_password("", auth_hash)
            empty_times.append(time.perf_counter() - start)

        correct_times = []

        for _ in range(50):
            start = time.perf_counter()
            self.key_derivation.verify_password(self.test_password, auth_hash)
            correct_times.append(time.perf_counter() - start)

        avg_empty = statistics.mean(empty_times)
        avg_correct = statistics.mean(correct_times)

        assert abs(avg_empty - avg_correct) < 0.01

    def test_verify_with_nonexistent_hash(self):
        nonexistent_hash = "$argon2id$v=19$m=65536,t=3,p=4$nonexistentsalt$nonexistenthash"

        times = []

        for _ in range(50):
            start = time.perf_counter()
            self.key_derivation.verify_password(self.test_password, nonexistent_hash)
            times.append(time.perf_counter() - start)

        avg_time = statistics.mean(times)

        correct_hash, _ = self.key_derivation.create_auth_hash(self.test_password)
        start = time.perf_counter()
        self.key_derivation.verify_password(self.test_password, correct_hash)
        correct_time = time.perf_counter() - start

        assert abs(avg_time - correct_time) < 0.01

    def test_authentication_backoff_timing(self):
        stored_hash, _ = self.key_derivation.create_auth_hash(self.test_password)

        times = []

        for _ in range(3):
            start = time.perf_counter()
            self.auth_service.verify_master_password("wrong", stored_hash)
            times.append(time.perf_counter() - start)

        assert times[0] < times[1] < times[2]

    def test_compare_digest_used(self):
        import inspect
        from src.core.crypto.key_derivation import KeyDerivation

        source = inspect.getsource(KeyDerivation.verify_password)

        assert "secrets.compare_digest" in source