# crypto.py
import os
from typing import Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# -------- Symmetric: AES-GCM --------
def aes_generate_key() -> bytes:
    return os.urandom(32)  # 256-bit

def encrypt_aes_gcm(key: bytes, data: bytes) -> bytes:
    # returns nonce + ciphertext + tag (AESGCM automatically includes tag)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, data, None)
    return nonce + ct

def decrypt_aes_gcm(key: bytes, blob: bytes) -> bytes:
    nonce, ct = blob[:12], blob[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)

# -------- Symmetric: ChaCha20-Poly1305 --------
def chacha20_generate_key() -> bytes:
    return os.urandom(32)

def encrypt_chacha(key: bytes, data: bytes) -> bytes:
    chacha = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    ct = chacha.encrypt(nonce, data, None)
    return nonce + ct

def decrypt_chacha(key: bytes, blob: bytes) -> bytes:
    nonce, ct = blob[:12], blob[12:]
    chacha = ChaCha20Poly1305(key)
    return chacha.decrypt(nonce, ct, None)

# -------- RSA for key wrapping --------
def generate_rsa_keypair(key_size: int = 2048) -> Tuple[bytes, bytes]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    priv_bytes = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return priv_bytes, pub_bytes

def rsa_wrap_key(pub_pem: bytes, key: bytes) -> bytes:
    public_key = serialization.load_pem_public_key(pub_pem)
    wrapped = public_key.encrypt(
        key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)
    )
    return wrapped

def rsa_unwrap_key(priv_pem: bytes, wrapped_key: bytes) -> bytes:
    private_key = serialization.load_pem_private_key(priv_pem, password=None)
    key = private_key.decrypt(
        wrapped_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)
    )
    return key

# Helpers: choose algorithm
def encrypt_file_with_algo(algo: str, key: bytes, data: bytes) -> bytes:
    if algo.lower() == "aes":
        return encrypt_aes_gcm(key, data)
    elif algo.lower() == "chacha":
        return encrypt_chacha(key, data)
    else:
        raise ValueError("Unknown algorithm")

def decrypt_file_with_algo(algo: str, key: bytes, blob: bytes) -> bytes:
    if algo.lower() == "aes":
        return decrypt_aes_gcm(key, blob)
    elif algo.lower() == "chacha":
        return decrypt_chacha(key, blob)
    else:
        raise ValueError("Unknown algorithm")