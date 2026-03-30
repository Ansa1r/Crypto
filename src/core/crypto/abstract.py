from abc import ABC, abstractmethod
from typing import Optional

class EncryptionService(ABC):
    def __init__(self, key_manager):
        self.key_manager = key_manager

    @abstractmethod
    def encrypt(self, data: bytes) -> bytes:
        pass

    @abstractmethod
    def decrypt(self, encrypted_data: bytes) -> bytes:
        pass

    def get_encryption_key(self) -> Optional[bytes]:
        return self.key_manager.get_encryption_key()