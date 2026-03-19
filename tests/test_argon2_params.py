import pytest
from src.core.crypto.key_derivation import KeyDerivation
import time


def test_argon2_default_params():
    kd = KeyDerivation()
    password = "TestPassword123!"

    auth_hash, params = kd.create_auth_hash(password)

    assert params['time_cost'] == 3
    assert params['memory_cost'] == 65536
    assert params['parallelism'] == 4
    assert params['hash_len'] == 32
    assert params['salt_len'] == 16
    assert params['algorithm'] == 'argon2id'

    assert kd.verify_password(password, auth_hash) is True


def test_argon2_custom_params():
    config = {
        'argon2_time': 5,
        'argon2_memory': 131072,
        'argon2_parallelism': 8
    }
    kd = KeyDerivation(config)
    password = "TestPassword123!"

    auth_hash, params = kd.create_auth_hash(password)

    assert params['time_cost'] == 5
    assert params['memory_cost'] == 131072
    assert params['parallelism'] == 8

    assert kd.verify_password(password, auth_hash) is True


def test_argon2_different_salts():
    kd = KeyDerivation()
    password = "TestPassword123!"

    hash1, params1 = kd.create_auth_hash(password)
    hash2, params2 = kd.create_auth_hash(password)

    assert hash1 != hash2

    assert kd.verify_password(password, hash1) is True
    assert kd.verify_password(password, hash2) is True


def test_argon2_wrong_password():
    kd = KeyDerivation()
    password = "TestPassword123!"
    wrong_password = "WrongPassword123!"

    auth_hash, _ = kd.create_auth_hash(password)

    assert kd.verify_password(wrong_password, auth_hash) is False


def test_argon2_memory_usage():
    import psutil
    import os

    process = psutil.Process(os.getpid())
    memory_before = process.memory_info().rss

    kd = KeyDerivation()
    password = "x" * 100

    for _ in range(10):
        kd.create_auth_hash(password)

    memory_after = process.memory_info().rss
    memory_increase = memory_after - memory_before

    assert memory_increase < 100 * 1024 * 1024