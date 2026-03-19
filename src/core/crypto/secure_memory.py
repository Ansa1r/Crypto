import ctypes
import gc
import sys
import platform
import secrets

def secure_zero(data):
    if data is None or len(data) == 0:
        return

    try:
        if isinstance(data, bytearray):
            data[:] = b'\x00' * len(data)
        elif isinstance(data, memoryview):
            ctypes.memset(ctypes.addressof(data.obj), 0, len(data))
        elif isinstance(data, (bytes, str)):
            dummy = secrets.token_bytes(len(data))
            if isinstance(data, bytearray):
                data[:] = dummy
    except Exception:
        dummy = secrets.token_bytes(len(data))
        if isinstance(data, bytearray):
            data[:] = dummy

    gc.collect()

def lock_memory(ptr, size):
    if platform.system() == "Windows":
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel32.VirtualLock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        kernel32.VirtualLock(ptr, size)
    elif platform.system() == "Linux":
        libc = ctypes.CDLL("libc.so.6")
        libc.mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        libc.mlock(ptr, size)
    elif platform.system() == "Darwin":
        libc = ctypes.CDLL("libc.dylib")
        libc.mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        libc.mlock(ptr, size)

def unlock_memory(ptr, size):
    if platform.system() == "Windows":
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel32.VirtualUnlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        kernel32.VirtualUnlock(ptr, size)
    elif platform.system() in ["Linux", "Darwin"]:
        libc = ctypes.CDLL("libc.so.6" if platform.system() == "Linux" else "libc.dylib")
        libc.munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        libc.munlock(ptr, size)

class ProtectedMemory:
    def __init__(self, data):
        self.data = bytearray(data)
        self.ptr = None
        self.locked = False
        self.size = len(data)

    def __enter__(self):
        if self.size > 0:
            self.ptr = (ctypes.c_byte * self.size).from_buffer(self.data)
            lock_memory(ctypes.addressof(self.ptr), self.size)
            self.locked = True
        return self.data

    def __exit__(self, *args):
        if self.locked and self.ptr:
            unlock_memory(ctypes.addressof(self.ptr), self.size)
            secure_zero(self.data)
            self.locked = False

class SecureBytes(bytearray):
    def __del__(self):
        secure_zero(self)

    def __exit__(self, *args):
        secure_zero(self)

def get_secure_buffer(size):
    return SecureBytes(size)

def secure_wipe_bytes(data):
    if data:
        secure_zero(data)
    del data
    gc.collect()

def secure_wipe_str(s):
    if not s:
        return
    length = len(s)
    try:
        buf = ctypes.create_string_buffer(s.encode('utf-8'))
        ctypes.memset(ctypes.byref(buf), 0, length + 1)
    except Exception:
        pass
    dummy = secrets.token_hex(length // 2 + 1)[:length]
    s = dummy
    del s
    gc.collect()

def secure_compare(a, b):
    if isinstance(a, str) and isinstance(b, str):
        a_bytes = a.encode('utf-8')
        b_bytes = b.encode('utf-8')
    elif isinstance(a, bytes) and isinstance(b, bytes):
        a_bytes, b_bytes = a, b
    else:
        return False

    result = secrets.compare_digest(a_bytes, b_bytes)
    del a_bytes
    del b_bytes
    gc.collect()
    return result