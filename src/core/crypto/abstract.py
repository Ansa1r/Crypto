from abc import ABC, abstractmethod
from typing import Optional

class KeyManager(ABC):
    @abstractmethod
    def get_encryption_key(self) -> Optional[bytes]:
        pass

    @abstractmethod
    def is_unlocked(self) -> bool:
        pass

class EncryptionService(ABC):
    def __init__(self, key_manager: KeyManager):
        self.key_manager = key_manager

    @abstractmethod
    def encrypt(self, data: bytes) -> bytes:
        pass

    @abstractmethod
    def decrypt(self, data: bytes) -> bytes:
        pass

    def _get_key(self) -> bytes:
        key = self.key_manager.get_encryption_key()
        if key is None:
            raise RuntimeError("Encryption key not available")
        return key