import os
from base64 import urlsafe_b64encode, urlsafe_b64decode
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

def derive_key(master_password: str, salt: bytes, iterations: int = 200_000) -> bytes:
    """Derive a 32-byte key from a human password using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    key = kdf.derive(master_password.encode("utf-8"))
    return urlsafe_b64encode(key)  # Fernet expects urlsafe base64 key

def encrypt(plaintext: str, fernet_key: bytes) -> bytes:
    f = Fernet(fernet_key)
    return f.encrypt(plaintext.encode("utf-8"))

def decrypt(ciphertext: bytes, fernet_key: bytes) -> str:
    f = Fernet(fernet_key)
    return f.decrypt(ciphertext).decode("utf-8")
