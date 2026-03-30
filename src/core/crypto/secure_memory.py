import ctypes
import gc
import secrets


def secure_zero(data):
    if data is None or len(data) == 0:
        return

    try:
        if isinstance(data, bytearray):
            data[:] = b'\x00' * len(data)
        elif isinstance(data, memoryview):
            ctypes.memset(ctypes.addressof(data.obj), 0, len(data))
    except Exception:
        dummy = secrets.token_bytes(len(data))
        if isinstance(data, bytearray):
            data[:] = dummy

    gc.collect()


def secure_wipe_bytes(data):
    del data
    gc.collect()


class SecureBytes(bytearray):
    def __del__(self):
        secure_zero(self)

    def __exit__(self, *args):
        secure_zero(self)


def get_secure_buffer(size):
    return SecureBytes(size)


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