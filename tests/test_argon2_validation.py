import pytest
import time
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
        assert len(errors) == 1
        assert "cannot be less than" in errors[0]

    def test_invalid_time_cost_above_maximum(self):
        is_valid, errors = self.validator.validate_argon2_params(
            self.validator.max_argon2_time + 1,
            65536,
            4
        )

        assert is_valid is False
        assert len(errors) == 1
        assert "cannot exceed" in errors[0]

    def test_invalid_memory_cost_below_minimum(self):
        is_valid, errors = self.validator.validate_argon2_params(
            3,
            self.validator.min_argon2_memory - 1024,
            4
        )

        assert is_valid is False
        assert len(errors) == 1
        assert "cannot be less than" in errors[0]

    def test_invalid_memory_cost_above_maximum(self):
        is_valid, errors = self.validator.validate_argon2_params(
            3,
            self.validator.max_argon2_memory + 65536,
            4
        )

        assert is_valid is False
        assert len(errors) == 1
        assert "cannot exceed" in errors[0]

    def test_invalid_parallelism_below_minimum(self):
        is_valid, errors = self.validator.validate_argon2_params(
            3,
            65536,
            self.validator.min_argon2_parallelism - 1
        )

        assert is_valid is False
        assert len(errors) == 1
        assert "cannot be less than" in errors[0]

    def test_invalid_parallelism_above_maximum(self):
        is_valid, errors = self.validator.validate_argon2_params(
            3,
            65536,
            self.validator.max_argon2_parallelism + 1
        )

        assert is_valid is False
        assert len(errors) == 1
        assert "cannot exceed" in errors[0]

    def test_multiple_invalid_parameters(self):
        is_valid, errors = self.validator.validate_argon2_params(
            self.validator.max_argon2_time + 1,
            self.validator.min_argon2_memory - 1024,
            self.validator.max_argon2_parallelism + 1
        )

        assert is_valid is False
        assert len(errors) >= 3

    def test_parallelism_exceeds_memory_cost(self):
        memory_cost = 16384
        parallelism = 32

        is_valid, errors = self.validator.validate_argon2_params(3, memory_cost, parallelism)

        assert is_valid is False
        assert any("parallelism cannot exceed memory_cost / 1024" in e for e in errors)

    def test_sanitize_parameters(self):
        time_cost, memory_cost, parallelism = self.validator.sanitize_argon2_params(
            -10,
            1024,
            100
        )

        assert time_cost == self.validator.min_argon2_time
        assert memory_cost == self.validator.min_argon2_memory
        assert parallelism == self.validator.max_argon2_parallelism

    def test_sanitize_pbkdf2_parameters(self):
        iterations = self.validator.sanitize_pbkdf2_params(-1000)
        assert iterations == self.validator.min_pbkdf2_iterations

        iterations = self.validator.sanitize_pbkdf2_params(99999999)
        assert iterations == self.validator.max_pbkdf2_iterations

        iterations = self.validator.sanitize_pbkdf2_params(600000)
        assert iterations == 600000


class TestArgon2HashGeneration:

    def setup_method(self):
        self.key_derivation = KeyDerivation()
        self.test_password = "TestPassword123!"

    def test_hash_generation_with_default_params(self):
        auth_hash, salt = self.key_derivation.create_auth_hash(self.test_password)

        assert auth_hash is not None
        assert isinstance(auth_hash, str)
        assert len(auth_hash) > 0
        assert salt is not None
        assert len(salt) == 16

    def test_hash_generation_with_custom_params(self):
        config = {
            'argon2_time': 2,
            'argon2_memory': 32768,
            'argon2_parallelism': 2,
            'pbkdf2_iterations': 100000
        }
        key_derivation = KeyDerivation(config)
        auth_hash, salt = key_derivation.create_auth_hash(self.test_password)

        assert auth_hash is not None
        assert isinstance(auth_hash, str)
        assert salt is not None
        assert len(salt) == 16

    def test_different_passwords_produce_different_hashes(self):
        auth_hash1, _ = self.key_derivation.create_auth_hash("Password1!")
        auth_hash2, _ = self.key_derivation.create_auth_hash("Password2!")

        assert auth_hash1 != auth_hash2

    def test_same_password_with_different_salts_produce_different_hashes(self):
        config = {'argon2_time': 1, 'argon2_memory': 16384, 'argon2_parallelism': 1}
        key_derivation = KeyDerivation(config)

        auth_hash1, _ = key_derivation.create_auth_hash(self.test_password)
        auth_hash2, _ = key_derivation.create_auth_hash(self.test_password)

        assert auth_hash1 != auth_hash2

    def test_hash_verification_with_correct_password(self):
        auth_hash, salt = self.key_derivation.create_auth_hash(self.test_password)
        is_valid = self.key_derivation.verify_password(self.test_password, auth_hash)

        assert is_valid is True

    def test_hash_verification_with_incorrect_password(self):
        auth_hash, _ = self.key_derivation.create_auth_hash(self.test_password)
        is_valid = self.key_derivation.verify_password("WrongPassword123!", auth_hash)

        assert is_valid is False

    def test_hash_verification_with_empty_password(self):
        auth_hash, _ = self.key_derivation.create_auth_hash(self.test_password)
        is_valid = self.key_derivation.verify_password("", auth_hash)

        assert is_valid is False

    def test_hash_verification_with_nonexistent_hash(self):
        is_valid = self.key_derivation.verify_password(self.test_password, "nonexistent_hash")

        assert is_valid is False


class TestParameterValidationIntegration:

    def setup_method(self):
        self.validator = ParameterValidator()

    def test_combined_parameters_validation_valid(self):
        is_valid, errors = self.validator.validate_combined_params(3, 65536, 4, 600000)

        assert is_valid is True
        assert len(errors) == 0

    def test_combined_parameters_validation_invalid_time(self):
        is_valid, errors = self.validator.validate_combined_params(20, 65536, 4, 600000)

        assert is_valid is False
        assert any("time_cost" in e.lower() for e in errors)

    def test_combined_parameters_validation_invalid_memory(self):
        is_valid, errors = self.validator.validate_combined_params(3, 1024, 4, 600000)

        assert is_valid is False
        assert any("memory" in e.lower() for e in errors)

    def test_combined_parameters_validation_invalid_parallelism(self):
        is_valid, errors = self.validator.validate_combined_params(3, 65536, 100, 600000)

        assert is_valid is False
        assert any("parallelism" in e.lower() for e in errors)

    def test_combined_parameters_validation_invalid_pbkdf2(self):
        is_valid, errors = self.validator.validate_combined_params(3, 65536, 4, 50000)

        assert is_valid is False
        assert any("iterations" in e.lower() for e in errors)

    def test_estimation_time_calculation(self):
        estimated_ms = self.validator.estimate_derivation_time(3, 65536, 4, 600000)

        assert isinstance(estimated_ms, int)
        assert estimated_ms > 0
        assert estimated_ms < 5000

    def test_estimation_time_increases_with_higher_params(self):
        low_estimated = self.validator.estimate_derivation_time(1, 16384, 1, 100000)
        high_estimated = self.validator.estimate_derivation_time(5, 131072, 8, 1000000)

        assert high_estimated > low_estimated


class TestPasswordStrengthValidation:

    def setup_method(self):
        self.validator = PasswordValidator()

    def test_password_too_short(self):
        is_valid, errors = self.validator.validate("short")

        assert is_valid is False
        assert any("at least 12 characters" in e for e in errors)

    def test_password_missing_uppercase(self):
        is_valid, errors = self.validator.validate("lowercase123!")

        assert is_valid is False
        assert any("uppercase letter" in e for e in errors)

    def test_password_missing_lowercase(self):
        is_valid, errors = self.validator.validate("UPPERCASE123!")

        assert is_valid is False
        assert any("lowercase letter" in e for e in errors)

    def test_password_missing_digits(self):
        is_valid, errors = self.validator.validate("NoDigitsHere!")

        assert is_valid is False
        assert any("digit" in e for e in errors)

    def test_password_missing_symbols(self):
        is_valid, errors = self.validator.validate("NoSymbolsHere123")

        assert is_valid is False
        assert any("special character" in e for e in errors)

    def test_strong_password_valid(self):
        is_valid, errors = self.validator.validate("StrongP@ssw0rd123!")

        assert is_valid is True
        assert len(errors) == 0

    def test_common_password_detected(self):
        is_valid, errors = self.validator.validate("password123!")

        assert is_valid is False
        assert any("common" in e.lower() for e in errors)

    def test_password_strength_score_calculation(self):
        weak_password = "abc"
        medium_password = "Medium123!"
        strong_password = "Str0ngP@ssw0rdWithLength!"

        weak_score = self.validator.get_strength_score(weak_password)
        medium_score = self.validator.get_strength_score(medium_password)
        strong_score = self.validator.get_strength_score(strong_password)

        assert weak_score < medium_score
        assert medium_score < strong_score
        assert weak_score <= 10
        assert medium_score <= 10
        assert strong_score <= 10

    def test_strength_label_correct(self):
        assert self.validator.get_strength_label(0) == "Very Weak"
        assert self.validator.get_strength_label(2) == "Very Weak"
        assert self.validator.get_strength_label(3) == "Weak"
        assert self.validator.get_strength_label(4) == "Weak"
        assert self.validator.get_strength_label(5) == "Moderate"
        assert self.validator.get_strength_label(6) == "Moderate"
        assert self.validator.get_strength_label(7) == "Strong"
        assert self.validator.get_strength_label(8) == "Strong"
        assert self.validator.get_strength_label(9) == "Very Strong"
        assert self.validator.get_strength_label(10) == "Very Strong"


class TestArgon2MemorySafety:

    def setup_method(self):
        self.key_derivation = KeyDerivation()
        self.test_password = "TestPassword123!"

    def test_hash_verification_timing_consistency(self):
        auth_hash, _ = self.key_derivation.create_auth_hash(self.test_password)

        import time

        correct_times = []
        incorrect_times = []

        for _ in range(50):
            start = time.perf_counter()
            self.key_derivation.verify_password(self.test_password, auth_hash)
            correct_times.append(time.perf_counter() - start)

            start = time.perf_counter()
            self.key_derivation.verify_password("wrong_password", auth_hash)
            incorrect_times.append(time.perf_counter() - start)

        avg_correct = sum(correct_times) / len(correct_times)
        avg_incorrect = sum(incorrect_times) / len(incorrect_times)

        time_ratio = max(avg_correct, avg_incorrect) / min(avg_correct, avg_incorrect)

        assert time_ratio < 2.0


class TestParameterValidatorEdgeCases:

    def setup_method(self):
        self.validator = ParameterValidator()

    def test_zero_time_cost(self):
        is_valid, errors = self.validator.validate_argon2_params(0, 65536, 4)

        assert is_valid is False
        assert any("cannot be less than" in e for e in errors)

    def test_zero_memory_cost(self):
        is_valid, errors = self.validator.validate_argon2_params(3, 0, 4)

        assert is_valid is False
        assert any("cannot be less than" in e for e in errors)

    def test_zero_parallelism(self):
        is_valid, errors = self.validator.validate_argon2_params(3, 65536, 0)

        assert is_valid is False
        assert any("cannot be less than" in e for e in errors)

    def test_negative_parameters(self):
        is_valid, errors = self.validator.validate_argon2_params(-1, -1, -1)

        assert is_valid is False
        assert len(errors) >= 3

    def test_float_parameters_are_rejected(self):
        is_valid, errors = self.validator.validate_argon2_params(3.5, 65536.0, 4)

        assert is_valid is False
        assert any("must be an integer" in e for e in errors)

    def test_string_parameters_are_rejected(self):
        is_valid, errors = self.validator.validate_argon2_params("3", "65536", "4")

        assert is_valid is False
        assert any("must be an integer" in e for e in errors)


class TestArgon2HashFormat:

    def setup_method(self):
        self.key_derivation = KeyDerivation()
        self.test_password = "TestPassword123!"

    def test_hash_contains_argon2_identifier(self):
        auth_hash, _ = self.key_derivation.create_auth_hash(self.test_password)

        assert "$argon2id$" in auth_hash

    def test_hash_contains_parameters(self):
        auth_hash, _ = self.key_derivation.create_auth_hash(self.test_password)

        assert "v=19" in auth_hash
        assert "m=" in auth_hash
        assert "t=" in auth_hash
        assert "p=" in auth_hash

    def test_hash_length_is_consistent(self):
        hash_lengths = []

        for _ in range(10):
            auth_hash, _ = self.key_derivation.create_auth_hash(self.test_password)
            hash_lengths.append(len(auth_hash))

        assert all(length == hash_lengths[0] for length in hash_lengths)

    def test_salt_in_hash(self):
        auth_hash, salt = self.key_derivation.create_auth_hash(self.test_password)

        salt_hex = salt.hex()
        assert len(salt_hex) == 32