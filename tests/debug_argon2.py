from src.core.crypto.key_derivation import KeyDerivation

kd = KeyDerivation()

hash_value = kd.auth_hash("test1234567890!")

print("HASH:", hash_value)
print("VERIFY CORRECT:", kd.verify("test1234567890!", hash_value))
print("VERIFY WRONG:", kd.verify("wrong", hash_value))