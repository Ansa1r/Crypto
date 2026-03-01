from src.core.crypto.placeholder import AES256Placeholder

def test_encrypt_decrypt():
    service = AES256Placeholder()
    data = b"my very secret password 123"
    key = b"testkey12345678"
    encrypted = service.encrypt(data, key)
    decrypted = service.decrypt(encrypted, key)
    assert decrypted == data

def test_diff_key_fails():
    service = AES256Placeholder()
    data = b"important"
    key1 = b"correct_key"
    key2 = b"wrong_key___"
    encrypted = service.encrypt(data, key1)
    decrypted = service.decrypt(encrypted, key2)
    assert decrypted != data