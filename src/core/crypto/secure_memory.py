import ctypes
import secrets
import gc
from typing import Optional, Union

def secure_zero_bytes(data: Optional[bytes]) -> None:
    if data is None or len(data) == 0:
        return
    try:
        buf = (ctypes.c_char * len(data)).from_buffer_copy(data)
        ctypes.memset(ctypes.byref(buf), 0, len(data))
    except Exception:
        secrets.token_bytes(len(data))
    del data
    gc.collect()

def secure_wipe_str(s: Optional[str]) -> None:
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


def secure_compare(a: Union[str, bytes], b: Union[str, bytes]) -> bool:
    if isinstance(a, str) and isinstance(b, str):
        a_bytes = a.encode('utf-8')
        b_bytes = b.encode('utf-8')
    elif isinstance(a, bytes) and isinstance(b, bytes):
        a_bytes, b_bytes = a, b
    else:
        return False

    result = secrets.compare_digest(a_bytes, b_bytes)
    secure_zero_bytes(a_bytes)
    secure_zero_bytes(b_bytes)

    return result