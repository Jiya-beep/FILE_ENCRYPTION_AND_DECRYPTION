import json, os, hashlib, base64, hmac

USERS_FILE = "users.json"

def _load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    if os.path.getsize(USERS_FILE) == 0:
        return {}
    try:
        with open(USERS_FILE, "r") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return {}

def _save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=4)

def create_user(username, password):
    users = _load_users()
    if username in users:
        raise ValueError("User already exists")
    salt = os.urandom(16)
    pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200000)
    users[username] = {
        "salt": base64.b64encode(salt).decode(),
        "hash": base64.b64encode(pwd_hash).decode(),
    }
    _save_users(users)

def verify_user(username, password):
    users = _load_users()
    if username not in users:
        return False
    salt = base64.b64decode(users[username]["salt"])
    stored = base64.b64decode(users[username]["hash"])
    attempt = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200000)
    return hmac.compare_digest(attempt, stored)
