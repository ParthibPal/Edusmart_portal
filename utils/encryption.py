from cryptography.fernet import Fernet

def generate_key():
    key = Fernet.generate_key()
    with open('secret.key', 'wb') as key_file:
        key_file.write(key)

# Run this once to generate the key
generate_key()
def load_key():
    return open('secret.key', 'rb').read()

def encrypt_data(data: str) -> bytes:
    key = load_key()
    f = Fernet(key)
    return f.encrypt(data.encode())

def decrypt_data(token: bytes) -> str:
    key = load_key()
    f = Fernet(key)
    return f.decrypt(token).decode()
