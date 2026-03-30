import math
from typing import Tuple, List, Optional


class ParameterValidator:
    def __init__(self):
        self.max_argon2_time = 10
        self.max_argon2_memory = 524288
        self.max_argon2_parallelism = 16
        self.max_pbkdf2_iterations = 2000000
        self.max_key_derivation_time_ms = 5000

        self.min_argon2_time = 1
        self.min_argon2_memory = 8192
        self.min_argon2_parallelism = 1
        self.min_pbkdf2_iterations = 100000

    def validate_argon2_params(self, time_cost: int, memory_cost: int, parallelism: int) -> Tuple[bool, List[str]]:
        errors = []

        if not isinstance(time_cost, int):
            errors.append("time_cost must be an integer")
        elif time_cost < self.min_argon2_time:
            errors.append(f"time_cost cannot be less than {self.min_argon2_time}")
        elif time_cost > self.max_argon2_time:
            errors.append(f"time_cost cannot exceed {self.max_argon2_time}")

        if not isinstance(memory_cost, int):
            errors.append("memory_cost must be an integer")
        elif memory_cost < self.min_argon2_memory:
            errors.append(f"memory_cost cannot be less than {self.min_argon2_memory} KB")
        elif memory_cost > self.max_argon2_memory:
            errors.append(f"memory_cost cannot exceed {self.max_argon2_memory} KB")

        if not isinstance(parallelism, int):
            errors.append("parallelism must be an integer")
        elif parallelism < self.min_argon2_parallelism:
            errors.append(f"parallelism cannot be less than {self.min_argon2_parallelism}")
        elif parallelism > self.max_argon2_parallelism:
            errors.append(f"parallelism cannot exceed {self.max_argon2_parallelism}")

        estimated_memory_mb = memory_cost / 1024
        if estimated_memory_mb > 512:
            errors.append(
                f"Estimated memory usage ({estimated_memory_mb:.0f} MB) exceeds recommended maximum of 512 MB")

        if parallelism > memory_cost / 1024:
            errors.append("parallelism cannot exceed memory_cost / 1024")

        return len(errors) == 0, errors

    def validate_pbkdf2_params(self, iterations: int) -> Tuple[bool, List[str]]:
        errors = []

        if not isinstance(iterations, int):
            errors.append("iterations must be an integer")
        elif iterations < self.min_pbkdf2_iterations:
            errors.append(f"iterations cannot be less than {self.min_pbkdf2_iterations}")
        elif iterations > self.max_pbkdf2_iterations:
            errors.append(f"iterations cannot exceed {self.max_pbkdf2_iterations}")

        return len(errors) == 0, errors

    def validate_combined_params(self, argon2_time: int, argon2_memory: int, argon2_parallelism: int,
                                 pbkdf2_iterations: int) -> Tuple[bool, List[str]]:
        errors = []

        is_valid_argon2, argon2_errors = self.validate_argon2_params(argon2_time, argon2_memory, argon2_parallelism)
        if not is_valid_argon2:
            errors.extend(argon2_errors)

        is_valid_pbkdf2, pbkdf2_errors = self.validate_pbkdf2_params(pbkdf2_iterations)
        if not is_valid_pbkdf2:
            errors.extend(pbkdf2_errors)

        if len(errors) == 0:
            estimated_time_ms = self.estimate_derivation_time(argon2_time, argon2_memory, argon2_parallelism,
                                                              pbkdf2_iterations)
            if estimated_time_ms > self.max_key_derivation_time_ms:
                errors.append(
                    f"Estimated derivation time ({estimated_time_ms} ms) exceeds maximum of {self.max_key_derivation_time_ms} ms")

        return len(errors) == 0, errors

    def estimate_derivation_time(self, argon2_time: int, argon2_memory: int, argon2_parallelism: int,
                                 pbkdf2_iterations: int) -> int:
        argon2_base_time = 50
        argon2_time_factor = argon2_time
        argon2_memory_factor = math.log2(argon2_memory / 1024)
        argon2_parallelism_factor = math.sqrt(argon2_parallelism)

        argon2_estimated_ms = argon2_base_time * argon2_time_factor * argon2_memory_factor / argon2_parallelism_factor

        pbkdf2_base_time = 0.5
        pbkdf2_estimated_ms = pbkdf2_base_time * (pbkdf2_iterations / 100000)

        total_ms = int(argon2_estimated_ms + pbkdf2_estimated_ms)

        return max(1, total_ms)

    def sanitize_argon2_params(self, time_cost: int, memory_cost: int, parallelism: int) -> Tuple[int, int, int]:
        time_cost = max(self.min_argon2_time, min(time_cost, self.max_argon2_time))
        memory_cost = max(self.min_argon2_memory, min(memory_cost, self.max_argon2_memory))
        parallelism = max(self.min_argon2_parallelism, min(parallelism, self.max_argon2_parallelism))

        return time_cost, memory_cost, parallelism

    def sanitize_pbkdf2_params(self, iterations: int) -> int:
        return max(self.min_pbkdf2_iterations, min(iterations, self.max_pbkdf2_iterations))

    def get_safe_defaults(self) -> dict:
        return {
            'argon2_time': 3,
            'argon2_memory': 65536,
            'argon2_parallelism': 4,
            'pbkdf2_iterations': 600000
        }

    def get_recommended_maximums(self) -> dict:
        return {
            'argon2_time': self.max_argon2_time,
            'argon2_memory': self.max_argon2_memory,
            'argon2_parallelism': self.max_argon2_parallelism,
            'pbkdf2_iterations': self.max_pbkdf2_iterations,
            'estimated_time_ms': self.max_key_derivation_time_ms
        }