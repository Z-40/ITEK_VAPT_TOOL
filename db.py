"""
Database access layer for the ITEK VAPT Orchestrator.

Replaces the old in-memory `users_db` dict with a real MySQL-backed store.
All functions here take/return plain dicts so the rest of api.py barely
has to change shape.
"""

from dotenv import load_dotenv
load_dotenv()

import os
from contextlib import contextmanager

import bcrypt
import mysql.connector
from mysql.connector import pooling

# ---------------------------------------------------------------- #
# Connection pool
# ---------------------------------------------------------------- #
DB_CONFIG = {
    "host": os.getenv("DB_HOST", "127.0.0.1"),
    "port": int(os.getenv("DB_PORT", "3306")),
    "user": os.getenv("DB_USER", "itek_app"),
    "password": os.getenv("DB_PASSWORD", ""),
    "database": os.getenv("DB_NAME", "itek_vapt"),
    "autocommit": False,
}

_pool = pooling.MySQLConnectionPool(
    pool_name="itek_pool",
    pool_size=int(os.getenv("DB_POOL_SIZE", "5")),
    **DB_CONFIG,
)


@contextmanager
def get_conn():
    conn = _pool.get_connection()
    try:
        yield conn
    finally:
        conn.close()


@contextmanager
def get_cursor(commit=False):
    with get_conn() as conn:
        cur = conn.cursor(dictionary=True)
        try:
            yield cur
            if commit:
                conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cur.close()


# ---------------------------------------------------------------- #
# Password hashing
# ---------------------------------------------------------------- #
def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except ValueError:
        # Malformed hash in DB — treat as failed auth rather than crashing.
        return False


# ---------------------------------------------------------------- #
# User queries
# ---------------------------------------------------------------- #
def create_user(email: str, username: str, password: str,
                 company: str = "Operator", role: str = "Pentester", bio: str = ""):
    """Creates a user plus a default workspace project. Raises ValueError if
    email or username is already taken."""
    with get_cursor(commit=True) as cur:
        cur.execute("SELECT id FROM users WHERE email=%s OR username=%s", (email, username))
        if cur.fetchone():
            raise ValueError("Account exists")

        cur.execute(
            "INSERT INTO users (email, username, password_hash, company, role, bio) "
            "VALUES (%s, %s, %s, %s, %s, %s)",
            (email, username, hash_password(password), company, role, bio),
        )
        user_id = cur.lastrowid

        cur.execute(
            "INSERT INTO projects (user_id, name, visibility) VALUES (%s, %s, %s)",
            (user_id, "default-workspace", "Private"),
        )
    return user_id


def authenticate_user(email: str, password: str):
    """Returns the user row dict on success, or None on bad credentials."""
    with get_cursor() as cur:
        cur.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cur.fetchone()
    if not user or not verify_password(password, user["password_hash"]):
        return None
    return user


def get_profile_by_username(username: str):
    """Returns {username, projects: [{name, visibility, domains: [{name}]}]}
    or None if not found. Username lookup is case-insensitive to match the
    old mock's behavior."""
    with get_cursor() as cur:
        cur.execute("SELECT * FROM users WHERE LOWER(username)=LOWER(%s)", (username,))
        user = cur.fetchone()
        if not user:
            return None

        cur.execute("SELECT id, name, visibility FROM projects WHERE user_id=%s", (user["id"],))
        projects = cur.fetchall()

        for proj in projects:
            cur.execute("SELECT name FROM domains WHERE project_id=%s", (proj["id"],))
            proj["domains"] = cur.fetchall()  # [{"name": ...}, ...]

    return {"username": user["username"], "projects": projects}


# ---------------------------------------------------------------- #
# Project / domain queries
# ---------------------------------------------------------------- #
def get_project_id(username: str, project_name: str):
    with get_cursor() as cur:
        cur.execute(
            """SELECT p.id FROM projects p
               JOIN users u ON u.id = p.user_id
               WHERE LOWER(u.username)=LOWER(%s) AND p.name=%s""",
            (username, project_name),
        )
        row = cur.fetchone()
    return row["id"] if row else None


def add_domain(username: str, project_name: str, domain_name: str):
    project_id = get_project_id(username, project_name)
    if project_id is None:
        raise ValueError("Project not found")

    with get_cursor(commit=True) as cur:
        cur.execute(
            "INSERT IGNORE INTO domains (project_id, name) VALUES (%s, %s)",
            (project_id, domain_name),
        )


def remove_domain(username: str, project_name: str, domain_name: str):
    project_id = get_project_id(username, project_name)
    if project_id is None:
        raise ValueError("Project not found")

    with get_cursor(commit=True) as cur:
        cur.execute(
            "DELETE FROM domains WHERE project_id=%s AND name=%s",
            (project_id, domain_name),
        )


def domain_exists(username: str, project_name: str, domain_name: str) -> bool:
    project_id = get_project_id(username, project_name)
    if project_id is None:
        return False
    with get_cursor() as cur:
        cur.execute(
            "SELECT id FROM domains WHERE project_id=%s AND name=%s",
            (project_id, domain_name),
        )
        return cur.fetchone() is not None
    
def create_project(username: str, project_name: str, visibility: str = "Private"):
    """Inserts a new project record linked to the given username if it doesn't already exist."""
    with get_cursor() as cur:
        cur.execute("SELECT id FROM users WHERE LOWER(username)=LOWER(%s)", (username,))
        user = cur.fetchone()
        if not user:
            raise ValueError("User not found")
        
        # Check uniqueness within this user's scope
        cur.execute("SELECT id FROM projects WHERE user_id=%s AND LOWER(name)=LOWER(%s)", (user["id"], project_name))
        if cur.fetchone():
            raise ValueError("Project name already exists in your workspace")

    with get_cursor(commit=True) as cur:
        cur.execute(
            "INSERT INTO projects (user_id, name, visibility) VALUES (%s, %s, %s)",
            (user["id"], project_name, visibility),
        )
    return True


def delete_project(username: str, project_name: str):
    """Deletes a project record. Triggers an automatic cascading delete on dependent domains."""
    project_id = get_project_id(username, project_name)
    if project_id is None:
        raise ValueError("Project not found")
    
    with get_cursor(commit=True) as cur:
        cur.execute("DELETE FROM projects WHERE id=%s", (project_id,))
    return True

