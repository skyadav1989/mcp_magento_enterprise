import pytest
from cryptography.fernet import InvalidToken
from app.services.crypto import encrypt, decrypt

def test_crypto_roundtrip():
    secret = "magento-integration-token-xyz123"
    encrypted = encrypt(secret)
    assert encrypted != secret
    decrypted = decrypt(encrypted)
    assert decrypted == secret

def test_crypto_empty_string():
    secret = ""
    encrypted = encrypt(secret)
    assert decrypt(encrypted) == secret

def test_crypto_invalid_ciphertext():
    with pytest.raises(Exception):
        decrypt("invalid-token-string")
