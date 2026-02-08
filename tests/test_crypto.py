from src.core.crypto.placeholder import AES256Placeholder


def test_encrypt_decrypt():
    crypto = AES256Placeholder()
    data = b"secret"
    key = b"key"

    encrypted = crypto.encrypt(data, key)
    decrypted = crypto.decrypt(encrypted, key)

    assert decrypted == data
