# crypto.py
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def _check_key(key: bytes):
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes (256-bit)")

def encrypt_aes(key: bytes, data: bytes) -> bytes:
    _check_key(key)
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct_bytes = iv + cipher.encrypt(pad(data, AES.block_size))
    return ct_bytes

def decrypt_aes(key: bytes, blob: bytes) -> bytes:
    _check_key(key)
    iv = blob[:16]
    ct = blob[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt
