# db.py
import sqlite3
import time
from typing import Optional, Dict

DB_FILE = "encrypt_ease.db"

def _get_conn():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        salt BLOB,
        pwdhash BLOB,
        created_at REAL
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        action TEXT,
        file_path TEXT,
        timestamp REAL
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS stats (
        key TEXT PRIMARY KEY,
        value INTEGER
    )
    """)
    # init files_encrypted stat
    cur.execute("INSERT OR IGNORE INTO stats(key, value) VALUES(?, ?)", ("files_encrypted", 0))
    conn.commit()
    conn.close()

def add_user(username: str, salt: bytes, pwdhash: bytes):
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("INSERT INTO users(username, salt, pwdhash, created_at) VALUES(?, ?, ?, ?)",
                (username, salt, pwdhash, time.time()))
    conn.commit()
    conn.close()

def get_user(username: str) -> Optional[Dict]:
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("SELECT username, salt, pwdhash FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    return {"username": row["username"], "salt": row["salt"], "pwdhash": row["pwdhash"]}

def log_action(username: str, action: str, file_path: str = ""):
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("INSERT INTO logs(username, action, file_path, timestamp) VALUES(?,?,?,?)",
                (username, action, file_path, time.time()))
    conn.commit()
    conn.close()

def increment_files_encrypted(n: int = 1):
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("UPDATE stats SET value = value + ? WHERE key = ?", (n, "files_encrypted"))
    conn.commit()
    conn.close()

def get_stats():
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("SELECT key, value FROM stats")
    rows = cur.fetchall()
    conn.close()
    return {r["key"]: r["value"] for r in rows}
