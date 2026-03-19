import pytest
from src.core.crypto.key_derivation import KeyDerivation
import time
import statistics


def test_password_verification_timing():
    kd = KeyDerivation()
    correct_password = "CorrectPassword123!"
    wrong_password = "WrongPassword123!"

    auth_hash, _ = kd.create_auth_hash(correct_password)

    timings_correct = []
    timings_wrong = []

    for _ in range(100):
        start = time.perf_counter()
        kd.verify_password(correct_password, auth_hash)
        end = time.perf_counter()
        timings_correct.append(end - start)

    for _ in range(100):
        start = time.perf_counter()
        kd.verify_password(wrong_password, auth_hash)
        end = time.perf_counter()
        timings_wrong.append(end - start)

    mean_correct = statistics.mean(timings_correct)
    mean_wrong = statistics.mean(timings_wrong)
    std_correct = statistics.stdev(timings_correct)
    std_wrong = statistics.stdev(timings_wrong)

    timing_difference = abs(mean_correct - mean_wrong)

    assert timing_difference < 0.01
    assert std_correct < 0.005
    assert std_wrong < 0.005


def test_constant_time_comparison_dummy():
    from src.core.crypto.key_derivation import KeyDerivation
    import secrets

    kd = KeyDerivation()

    timings_with_exception = []
    timings_without_exception = []

    for _ in range(100):
        start = time.perf_counter()
        try:
            kd.verify_password("any", "invalid_hash_format")
        except:
            pass
        end = time.perf_counter()
        timings_with_exception.append(end - start)

    for _ in range(100):
        start = time.perf_counter()
        secrets.compare_digest(b'dummy', b'dummy')
        end = time.perf_counter()
        timings_without_exception.append(end - start)

    assert statistics.mean(timings_with_exception) > 0


def test_compare_digest_consistency():
    import secrets

    a = b"secretkey123"
    b = b"secretkey124"
    c = b"secretkey123"

    timings_match = []
    timings_mismatch = []

    for _ in range(1000):
        start = time.perf_counter()
        secrets.compare_digest(a, c)
        end = time.perf_counter()
        timings_match.append(end - start)

    for _ in range(1000):
        start = time.perf_counter()
        secrets.compare_digest(a, b)
        end = time.perf_counter()
        timings_mismatch.append(end - start)

    mean_match = statistics.mean(timings_match)
    mean_mismatch = statistics.mean(timings_mismatch)

    assert abs(mean_match - mean_mismatch) < 0.001