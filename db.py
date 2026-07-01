"""
Database access layer for the ITEK VAPT Orchestrator.
MySQL handles user accounts and credentials ONLY. It has zero awareness
of projects, domains, tasks, states, or the filesystem layout.
"""

from dotenv import load_dotenv
load_dotenv()

import os
from contextlib import contextmanager
import bcrypt
from mysql.connector import pooling

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "127.0.0.1"),
    "port": int(os.getenv("DB_PORT", "3306")),
    "user": os.getenv("DB_USER", "itek_app"),
    "password": os.getenv("DB_PASSWORD", ""),
    "database": os.getenv("DB_NAME", "itek_vapt"),
    "autocommit": False,
}

_pool = pooling.MySQLConnectionPool(pool_name="itek_pool", pool_size=5, **DB_CONFIG)

@contextmanager
def get_cursor(commit=False):
    conn = _pool.get_connection()
    cur = conn.cursor(dictionary=True)
    try:
        yield cur
        if commit: conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()
        conn.close()

def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def verify_password(plain: str, hashed: str) -> bool:
    try: 
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except ValueError: 
        return False

def create_user(email: str, username: str, password: str):
    with get_cursor(commit=True) as cur:
        cur.execute("SELECT id FROM users WHERE email=%s OR username=%s", (email, username))
        if cur.fetchone(): 
            raise ValueError("Account exists")
        cur.execute(
            "INSERT INTO users (email, username, password_hash) VALUES (%s, %s, %s)",
            (email, username, hash_password(password)),
        )
    return True

def authenticate_user(email: str, password: str):
    with get_cursor() as cur:
        cur.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cur.fetchone()
    if not user or not verify_password(password, user["password_hash"]): 
        return None
    return user