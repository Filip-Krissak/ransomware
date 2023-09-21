import pathlib
import secrets
import os
import base64
import getpass

import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

def generate_salt(size=16):
    return secrets.token_bytes(size)

def derive_key(salt,password):
    kdf = Scrypt(salt = salt,lenght = 32, n = 2**14, r = 8, p = 1)
    return kdf.derive(password.encode())

