import ctypes
import platform
import os


class SecureMemory:
    def __init__(self):
        self._is_windows = platform.system() == "Windows"
        self._is_unix = platform.system() in ("Linux", "Darwin")

    def protect(self, data: bytes) -> bytes:
        if not data:
            return b''

        protected = bytearray(data)

        if self._is_windows:
            try:
                ctypes.windll.kernel32.VirtualLock(
                    ctypes.byref((ctypes.c_char * len(protected)).from_buffer(protected)), len(protected))
            except:
                pass
        elif self._is_unix:
            try:
                libc = ctypes.CDLL(None)
                libc.mlock(ctypes.byref((ctypes.c_char * len(protected)).from_buffer(protected)), len(protected))
            except:
                pass

        return bytes(protected)

    def unprotect(self, data: bytes) -> bytes:
        if not data:
            return b''
        return bytes(data)

    def wipe(self, data: bytes):
        if not data:
            return

        try:
            length = len(data)
            buf = bytearray(data)

            for i in range(length):
                buf[i] = 0

            if self._is_windows:
                try:
                    ctypes.windll.kernel32.VirtualUnlock(ctypes.byref((ctypes.c_char * length).from_buffer(buf)),
                                                         length)
                except:
                    pass
            elif self._is_unix:
                try:
                    libc = ctypes.CDLL(None)
                    libc.munlock(ctypes.byref((ctypes.c_char * length).from_buffer(buf)), length)
                except:
                    pass

            buf[:] = b'\x00' * length
        except:
            pass