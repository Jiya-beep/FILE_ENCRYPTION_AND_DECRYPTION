# auth.py
import os, base64, hashlib, hmac
import db

# initialize DB on import
db.init_db()

ITERATIONS = 200000

def _hash_password(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS)

def create_user(username: str, password: str):
    if db.get_user(username):
        raise ValueError("User already exists")
    salt = os.urandom(16)
    pwdhash = _hash_password(password, salt)
    db.add_user(username, salt, pwdhash)

def verify_user(username: str, password: str) -> bool:
    row = db.get_user(username)
    if not row:
        return False
    salt = row["salt"]
    stored = row["pwdhash"]
    attempt = _hash_password(password, salt)
    return hmac.compare_digest(attempt, stored)
