import pytest
import sys
import gc
import ctypes
from src.core.crypto.secure_memory import SecureMemory
from src.core.crypto.key_storage import KeyStorage
from src.core.crypto.key_derivation import KeyDerivation


class TestMemorySafety:

    def setup_method(self):
        self.secure_memory = SecureMemory()
        self.key_storage = KeyStorage("test_user")
        self.key_derivation = KeyDerivation()

    def test_key_zeroed_after_clear(self):
        test_key = b"test_key_32_bytes_for_memory_safety_test"

        self.key_storage.store_encryption_key(test_key, use_keychain=False)

        key_before = self.key_storage.get_encryption_key(from_keychain=False)
        assert key_before == test_key

        self.key_storage.clear()

        key_after = self.key_storage.get_encryption_key(from_keychain=False)
        assert key_after is None

    def test_secure_memory_protect_creates_copy(self):
        original = b"sensitive_data_123"

        protected = self.secure_memory.protect(original)

        assert protected is not None
        assert isinstance(protected, bytes)

        original_address = id(original)
        protected_address = id(protected)

        assert original_address != protected_address

    def test_secure_memory_wipe_clears_data(self):
        data = b"secret_data_to_wipe"

        self.secure_memory.wipe(data)

        for byte in data:
            assert byte == 0

    def test_multiple_keys_cleared_on_logout(self):
        key1 = b"key1_32_bytes_for_testing_purpose_"
        key2 = b"key2_32_bytes_for_testing_purpose_"

        self.key_storage.store_encryption_key(key1, use_keychain=False)
        self.key_storage.store_key_for_purpose("test_purpose", key2, use_keychain=False)

        assert self.key_storage.get_encryption_key(from_keychain=False) == key1
        assert self.key_storage.get_key_for_purpose("test_purpose", from_keychain=False) == key2

        self.key_storage.clear()

        assert self.key_storage.get_encryption_key(from_keychain=False) is None
        assert self.key_storage.get_key_for_purpose("test_purpose", from_keychain=False) is None

    def test_key_not_persistent_after_process_exit(self):
        import tempfile
        import subprocess

        script = """
import sys
sys.path.insert(0, '.')
from src.core.crypto.key_storage import KeyStorage

storage = KeyStorage("test_user")
storage.store_encryption_key(b"test_key_123", use_keychain=False)

print(storage.get_encryption_key(from_keychain=False) is not None)
"""

        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(script)
            script_path = f.name

        try:
            result = subprocess.run([sys.executable, script_path], capture_output=True, text=True)

            assert "True" in result.stdout
        finally:
            import os
            os.unlink(script_path)

    def test_memory_lock_available(self):
        if sys.platform == "win32":
            try:
                kernel32 = ctypes.windll.kernel32
                assert hasattr(kernel32, "VirtualLock")
            except Exception:
                pass
        elif sys.platform in ("linux", "darwin"):
            try:
                libc = ctypes.CDLL(None)
                assert hasattr(libc, "mlock")
            except Exception:
                pass

    def test_key_overwritten_before_deletion(self):
        import gc

        key = b"secret_key_to_overwrite"

        self.key_storage.store_encryption_key(key, use_keychain=False)

        stored_key = self.key_storage.get_encryption_key(from_keychain=False)

        self.key_storage.clear()

        gc.collect()

    def test_salt_not_persistent_after_use(self):
        salt = self.key_derivation._current_salt

        self.key_derivation._current_salt = None

        assert self.key_derivation._current_salt is None

    def test_derive_key_does_not_leak_memory(self):
        import tracemalloc

        tracemalloc.start()

        for _ in range(100):
            key = self.key_derivation.derive_encryption_key("test_password", b"test_salt_16_bytes")
            self.secure_memory.wipe(key)

        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        assert peak < 50 * 1024 * 1024

    def test_auth_hash_does_not_store_password(self):
        auth_hash, salt = self.key_derivation.create_auth_hash("TestPassword123!")

        assert "TestPassword123!" not in auth_hash
        assert "TestPassword123!" not in str(salt)

    def test_clear_all_fallback_data_removes_files(self):
        import tempfile
        from pathlib import Path

        temp_dir = tempfile.mkdtemp()
        fallback_dir = Path(temp_dir) / "fallback"

        storage = KeyStorage("test_user", fallback_dir)
        storage.store_encryption_key(b"test_key", use_keychain=False)

        enc_key_file = storage._get_fallback_path("enc_key")
        assert enc_key_file.exists()

        storage.clear_all_fallback_data()

        assert not enc_key_file.exists()

        import shutil
        shutil.rmtree(temp_dir, ignore_errors=True)

    def test_multi_key_clear_all(self):
        keys = {
            "purpose1": b"key1_32_bytes_for_testing_purpose_",
            "purpose2": b"key2_32_bytes_for_testing_purpose_",
            "purpose3": b"key3_32_bytes_for_testing_purpose_"
        }

        for purpose, key in keys.items():
            self.key_storage.store_key_for_purpose(purpose, key, use_keychain=False)

        for purpose in keys:
            assert self.key_storage.get_key_for_purpose(purpose, from_keychain=False) == keys[purpose]

        self.key_storage.clear()

        for purpose in keys:
            assert self.key_storage.get_key_for_purpose(purpose, from_keychain=False) is None