import pytest
from src.core.crypto.key_derivation import KeyDerivation
import secrets


def test_pbkdf2_consistency():
    kd = KeyDerivation()
    password = "TestPassword123!"
    salt = secrets.token_bytes(16)

    key1 = kd.derive_encryption_key(password, salt)
    key2 = kd.derive_encryption_key(password, salt)

    assert key1 == key2
    assert len(key1) == 32


def test_pbkdf2_different_passwords():
    kd = KeyDerivation()
    salt = secrets.token_bytes(16)

    key1 = kd.derive_encryption_key("Password1!", salt)
    key2 = kd.derive_encryption_key("Password2!", salt)

    assert key1 != key2


def test_pbkdf2_different_salts():
    kd = KeyDerivation()
    password = "TestPassword123!"
    salt1 = secrets.token_bytes(16)
    salt2 = secrets.token_bytes(16)

    key1 = kd.derive_encryption_key(password, salt1)
    key2 = kd.derive_encryption_key(password, salt2)

    assert key1 != key2


def test_pbkdf2_iterations():
    config = {'pbkdf2_iterations': 1000}
    kd = KeyDerivation(config)
    password = "TestPassword123!"
    salt = secrets.token_bytes(16)

    import time
    start = time.time()
    key = kd.derive_encryption_key(password, salt)
    duration = time.time() - start

    assert duration < 1.0
    assert len(key) == 32


def test_hkdf_consistency():
    kd = KeyDerivation()
    master_key = secrets.token_bytes(32)
    salt = secrets.token_bytes(16)

    audit_key1 = kd.derive_audit_key(master_key, salt)
    audit_key2 = kd.derive_audit_key(master_key, salt)

    assert audit_key1 == audit_key2
    assert len(audit_key1) == 32

    sharing_key = kd.derive_sharing_key(master_key, salt)
    assert sharing_key != audit_key1

    totp_key = kd.derive_totp_key(master_key, salt)
    assert len(totp_key) == 20