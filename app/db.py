# app/db.py
from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Optional

# Allow overriding DB location in tests via env var, otherwise app-local
_DEFAULT_DB_PATH = Path(__file__).with_name("jwks.db")
DB_PATH = Path(os.environ.get("JWKS_DB_PATH", str(_DEFAULT_DB_PATH)))


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create tables if they don't exist."""
    conn = get_connection()
    cur = conn.cursor()

    # Private keys table (encrypted)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS keys(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kid TEXT NOT NULL UNIQUE,
            enc_private_key BLOB NOT NULL,
            iv BLOB NOT NULL,
            public_jwk TEXT NOT NULL,
            expires_at INTEGER NOT NULL
        )
        """
    )

    # Users table (as specified)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE,
            date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
        """
    )

    # Auth logs table (as specified)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS auth_logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_ip TEXT NOT NULL,
            request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        """
    )

    conn.commit()
    conn.close()


def log_auth_success(request_ip: str, user_id: Optional[int]) -> None:
    """Insert a row into auth_logs for a successful /auth call."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)",
        (request_ip, user_id),
    )
    conn.commit()
    conn.close()
