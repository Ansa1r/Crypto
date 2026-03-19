import pytest
from src.core.crypto.secure_memory import secure_zero, ProtectedMemory, SecureBytes
import ctypes
import gc


def test_secure_zero_bytearray():
    data = bytearray(b"secret_password_123")
    data_copy = data.copy()

    secure_zero(data)

    assert all(b == 0 for b in data)
    assert data != data_copy


def test_secure_zero_memoryview():
    original = bytearray(b"secret_key_456")
    mv = memoryview(original)

    secure_zero(mv)

    assert all(b == 0 for b in original)


def test_protected_memory_context():
    secret = b"super_secret_key_789"

    with ProtectedMemory(secret) as protected_data:
        assert bytes(protected_data) == secret
        assert protected_data is not None

    gc.collect()

    with ProtectedMemory(secret) as new_protected:
        assert bytes(new_protected) == secret


def test_secure_bytes_autowipe():
    data = SecureBytes(b"temporary_secret")
    data_copy = bytes(data)

    assert bytes(data) == data_copy

    del data
    gc.collect()

    import sys
    assert data_copy not in sys.modules


def test_key_cache_memory_wipe():
    from src.core.crypto.key_storage import SecureKeyCache

    cache = SecureKeyCache(timeout=1)
    test_key = b"cache_test_key_101"

    cache.set("test", test_key)
    assert cache.get("test") == test_key

    cache.delete("test")
    assert cache.get("test") is None

    retrieved = cache.get("test")
    assert retrieved is None


def test_multiple_secure_wipes():
    from src.core.crypto.secure_memory import secure_wipe_bytes

    data1 = bytearray(b"secret1")
    data2 = bytearray(b"secret2" * 100)
    data3 = bytearray(b"secret3" * 1000)

    secure_wipe_bytes(data1)
    secure_wipe_bytes(data2)
    secure_wipe_bytes(data3)

    assert all(b == 0 for b in data1)
    assert all(b == 0 for b in data2)
    assert all(b == 0 for b in data3)


def test_mlock_functionality():
    from src.core.crypto.secure_memory import lock_memory, unlock_memory
    import platform

    if platform.system() not in ["Linux", "Darwin", "Windows"]:
        pytest.skip("Platform does not support mlock")

    data = bytearray(b"lock_test_memory")
    ptr = (ctypes.c_byte * len(data)).from_buffer(data)

    try:
        lock_memory(ctypes.addressof(ptr), len(data))
        assert True
    except Exception as e:
        pytest.fail(f"mlock failed: {e}")
    finally:
        unlock_memory(ctypes.addressof(ptr), len(data))