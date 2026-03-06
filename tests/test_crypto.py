import pytest
from src.core.crypto.placeholder import AES256Placeholder

def test_placeholder_roundtrip():
    service = AES256Placeholder()
    key = b'test_key_16_bytes'
    plaintext = b"Hello, CryptoSafe!"

    ciphertext = service.encrypt(plaintext, key)
    decrypted = service.decrypt(ciphertext, key)

    assert decrypted == plaintext
    assert decrypted != ciphertext

def test_placeholder_different_keys():
    service = AES256Placeholder()
    key1 = b'key_one___________'
    key2 = b'key_two___________'

    data = b'Secret message'
    enc1 = service.encrypt(data, key1)
    enc2 = service.encrypt(data, key2)

    assert enc1 != enc2

    dec1 = service.decrypt(enc1, key1)
    assert dec1 == data

    dec_wrong = service.decrypt(enc1, key2)
    assert dec_wrong != data