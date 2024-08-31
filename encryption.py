# encryption.py

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

# Fernet encryption and decryption
def encrypt_string_fernet(data, key):
    f = Fernet(key)
    encrypted_data = f.encrypt(data.encode())
    return encrypted_data

def decrypt_string_fernet(encrypted_data, key):
    f = Fernet(key)
    decrypted_data = f.decrypt(encrypted_data).decode()
    return decrypted_data

# AES encryption and decryption
def encrypt_string_aes(data, key):
    backend = default_backend()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()
    encryptor = cipher.encryptor()
    encrypted_data = iv + encryptor.update(padded_data) + encryptor.finalize()
    return encrypted_data

def decrypt_string_aes(encrypted_data, key):
    backend = default_backend()
    iv = encrypted_data[:16]
    encrypted_data = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(decrypted_data) + unpadder.finalize()
    return data.decode()

# Triple DES encryption and decryption
def encrypt_string_3des(data, key):
    if len(key) != 24:
        raise ValueError("Invalid key size for Triple DES. Key must be 24 bytes.")
    backend = default_backend()
    iv = os.urandom(8)
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=backend)
    padder = padding.PKCS7(64).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()
    encryptor = cipher.encryptor()
    encrypted_data = iv + encryptor.update(padded_data) + encryptor.finalize()
    return encrypted_data

def decrypt_string_3des(encrypted_data, key):
    if len(key) != 24:
        raise ValueError("Invalid key size for Triple DES. Key must be 24 bytes.")
    backend = default_backend()
    iv = encrypted_data[:8]
    encrypted_data = encrypted_data[8:]
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(64).unpadder()
    data = unpadder.update(decrypted_data) + unpadder.finalize()
    return data.decode()

