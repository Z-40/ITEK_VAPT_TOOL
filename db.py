"""
Database access layer for the ITEK VAPT Orchestrator.
MySQL handles user accounts and credentials ONLY. It has zero awareness
of projects, domains, tasks, states, or the filesystem layout.
"""

from dotenv import load_dotenv
load_dotenv()

import os
import secrets
from datetime import datetime, timedelta, timezone
from contextlib import contextmanager
import bcrypt
from mysql.connector import pooling

# How long an email verification link stays valid before the user has to
# request a fresh one. 30 seconds was a bug -- real-world email delivery
# alone can take longer than that, so links were expiring before anyone
# could ever click them. 15 minutes is a reasonable default for a link
# (vs. e.g. a 10-min OTP) and is configurable via env var if needed.
VERIFICATION_TOKEN_TTL = timedelta(minutes=int(os.getenv("VERIFICATION_LINK_TTL_MINUTES", "15")))

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "127.0.0.1"),
    "port": int(os.getenv("DB_PORT", "3306")),
    "user": os.getenv("DB_USER", "itek_app"),
    "password": os.getenv("DB_PASSWORD", ""),
    "database": os.getenv("DB_NAME", "itek_vapt"),
    "autocommit": False,
}

_pool = pooling.MySQLConnectionPool(pool_name="itek_pool", pool_size=5, **DB_CONFIG)

def ensure_schema():
    """Adds the email-verification columns to `users` if they aren't there yet.
    Safe to call every startup -- checks information_schema first instead of
    blindly ALTERing, so it never errors on a database that's already migrated."""
    print(f"[db] verification link TTL is {VERIFICATION_TOKEN_TTL} "
          f"(override with VERIFICATION_LINK_TTL_MINUTES)")
    with get_cursor(commit=True) as cur:
        cur.execute(
            "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS "
            "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users'"
        )
        existing = {row["COLUMN_NAME"] for row in cur.fetchall()}
        if "email_verified" not in existing:
            cur.execute("ALTER TABLE users ADD COLUMN email_verified TINYINT(1) NOT NULL DEFAULT 0")
        if "verification_token" not in existing:
            cur.execute("ALTER TABLE users ADD COLUMN verification_token VARCHAR(64) NULL")
        if "verification_token_expires" not in existing:
            cur.execute("ALTER TABLE users ADD COLUMN verification_token_expires DATETIME NULL")
        if "verification_attempts" not in existing:
            cur.execute("ALTER TABLE users ADD COLUMN verification_attempts INT NOT NULL DEFAULT 0")
        if "verification_locked_until" not in existing:
            cur.execute("ALTER TABLE users ADD COLUMN verification_locked_until DATETIME NULL")

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

def create_user(email: str, username: str, password: str) -> str:
    """Creates the account in an unverified state and returns the verification
    token the caller (api.py) needs to email to the user."""
    token = secrets.token_urlsafe(32)
    expires = datetime.now(timezone.utc) + VERIFICATION_TOKEN_TTL
    with get_cursor(commit=True) as cur:
        cur.execute("SELECT id FROM users WHERE email=%s OR username=%s", (email, username))
        if cur.fetchone(): 
            raise ValueError("Account exists")
        cur.execute(
            "INSERT INTO users (email, username, password_hash, email_verified, "
            "verification_token, verification_token_expires, verification_attempts, "
            "verification_locked_until) VALUES (%s, %s, %s, 0, %s, %s, 0, NULL)",
            (email, username, hash_password(password), token, expires),
        )
    return token

def authenticate_user(email: str, password: str):
    with get_cursor() as cur:
        cur.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cur.fetchone()
    if not user or not verify_password(password, user["password_hash"]): 
        return None
    return user

def verify_email_token(token: str):
    """Consumes a verification token. Returns (status, email) where status is
    'ok', 'expired', or 'invalid'.

    email is the account's address whenever the token matched a row (even if
    expired), or None if the token is bogus. The caller (api.py) hands this
    back to the frontend so a fresh, unauthenticated tab that only has the
    token in the URL -- and no other session context -- can still offer a
    one-click "send me a new link" instead of a dead end.

    On 'expired' the token is left in place so regenerate_verification_token
    can reuse the row; on 'ok' the token is cleared so it can't be replayed."""
    with get_cursor(commit=True) as cur:
        # FOR UPDATE locks the matching row for the rest of this transaction.
        # verify-email gets hit more than once for the same token in practice
        # (React StrictMode's dev-mode double effect, a duplicate click, an
        # email-scanner prefetch, ...), so without a lock two near-simultaneous
        # calls can both read email_verified=0 and race each other -- one wins
        # and verifies the account while the other reports failure back to the
        # user even though the account is now verified. Locking here makes the
        # second caller wait for the first to commit, then see the row already
        # verified and correctly return "ok" instead of racing to a wrong answer.
        cur.execute(
            "SELECT id, email, email_verified, verification_token_expires FROM users "
            "WHERE verification_token=%s FOR UPDATE", (token,),
        )
        user = cur.fetchone()
        if not user:
            return "invalid", None
        if user["email_verified"]:
            return "ok", user["email"]  # already verified (e.g. link clicked twice) -- treat as success
        expires = user["verification_token_expires"]
        if expires and expires.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
            return "expired", user["email"]
        cur.execute(
            "UPDATE users SET email_verified=1, verification_token=NULL, "
            "verification_token_expires=NULL, verification_attempts=0, "
            "verification_locked_until=NULL WHERE id=%s", (user["id"],),
        )
    return "ok", user["email"]

def regenerate_verification_token(email: str):
    """Issues a fresh token for a not-yet-verified account. Returns the new
    token, or None if there's no such unverified account (caller should give
    a generic response either way so this can't be used to enumerate emails)."""
    token = secrets.token_urlsafe(32)
    expires = datetime.now(timezone.utc) + VERIFICATION_TOKEN_TTL
    with get_cursor(commit=True) as cur:
        cur.execute("SELECT id, email_verified FROM users WHERE email=%s", (email,))
        user = cur.fetchone()
        if not user or user["email_verified"]:
            return None
        cur.execute(
            "UPDATE users SET verification_token=%s, verification_token_expires=%s, "
            "verification_attempts=0, verification_locked_until=NULL WHERE id=%s",
            (token, expires, user["id"]),
        )
    return token