# app/users.py
from __future__ import annotations

from typing import Optional
from uuid import uuid4

from argon2 import PasswordHasher, exceptions as argon2_exceptions

from .db import get_connection

# Configurable Argon2 parameters (time, memory, parallelism, hash length)
_password_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=64 * 1024,  # 64 MB
    parallelism=2,
    hash_len=32,
)


def create_user(username: str, email: str) -> str:
    """
    Create a user with a random UUIDv4 password.
    Returns the plaintext password so it can be shown once in /register.
    """
    raw_password = str(uuid4())
    password_hash = _password_hasher.hash(raw_password)

    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
        (username, password_hash, email),
    )
    conn.commit()
    conn.close()

    return raw_password


def verify_user_credentials(username: str, password: str) -> Optional[int]:
    """
    Verify username/password using Argon2.
    Returns the user_id on success, or None on failure.
    """
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, password_hash FROM users WHERE username = ?",
        (username,),
    )
    row = cur.fetchone()
    conn.close()

    if row is None:
        return None

    try:
        _password_hasher.verify(row["password_hash"], password)
    except argon2_exceptions.VerifyMismatchError:
        return None

    return int(row["id"])
