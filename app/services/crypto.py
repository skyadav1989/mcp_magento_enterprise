"""Phase 2 secret-at-rest encryption using Fernet."""
from cryptography.fernet import Fernet
from ..config import get_settings

def _fernet():
    key = getattr(get_settings(), 'connection_encryption_key', '')
    if not key:
        raise RuntimeError('CONNECTION_ENCRYPTION_KEY must be configured')
    return Fernet(key.encode())

def encrypt(value: str) -> str:
    return _fernet().encrypt(value.encode()).decode()

def decrypt(value: str) -> str:
    return _fernet().decrypt(value.encode()).decode()
