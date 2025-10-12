from cryptography.fernet import Fernet, InvalidToken
import os

KEY_PATH = os.path.join(os.path.dirname(__file__), '..', 'secret.key')

def generate_key():
    """Run once to generate a new Fernet key."""
    key = Fernet.generate_key()
    with open(KEY_PATH, 'wb') as key_file:
        key_file.write(key)

def load_key():
    """Load the Fernet key from file."""
    with open(KEY_PATH, 'rb') as key_file:
        return key_file.read()

def encrypt_data(data: str) -> bytes:
    """Encrypt a string using Fernet."""
    key = load_key()
    f = Fernet(key)
    return f.encrypt(data.encode())

def decrypt_data(token: bytes) -> str:
    try:
        key = load_key()
        f = Fernet(key)
        return f.decrypt(token).decode()
    except InvalidToken:
        return "[Invalid or corrupted data]"