from __future__ import annotations

import time
import threading
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException, Query, Request, status
from jwcrypto import jwt
from pydantic import BaseModel

from .keystore import keystore, ManagedKey
from .db import init_db, log_auth_success
from .users import create_user, verify_user_credentials

# Initialize database (keys, users, auth_logs tables)
init_db()

# ---------------------------------------------------------------------------
# Rate limiter state (used by tests via app.main._rate_buckets/_rate_lock)
# ---------------------------------------------------------------------------

_RATE_LIMIT_MAX_REQUESTS = 10          # 10 requests per window
_RATE_LIMIT_WINDOW_SECONDS = 1.0       # 1-second window
_rate_buckets: Dict[str, list[float]] = {}
_rate_lock = threading.Lock()

app = FastAPI(title="JWKS Demo", version="1.1.0")


def _rate_limited(ip: str) -> bool:
    """Simple fixed-window rate limiter per IP."""
    now = time.time()
    with _rate_lock:
        bucket = _rate_buckets.setdefault(ip, [])
        cutoff = now - _RATE_LIMIT_WINDOW_SECONDS
        while bucket and bucket[0] < cutoff:
            bucket.pop(0)
        if len(bucket) >= _RATE_LIMIT_MAX_REQUESTS:
            return True
        bucket.append(now)
        return False


# ---------------------------------------------------------------------------
# JWKS endpoints
# ---------------------------------------------------------------------------


@app.get("/.well-known/jwks.json")
def get_well_known_jwks() -> Dict[str, Any]:
    """Standard JWKS endpoint. Returns only unexpired public keys."""
    return {"keys": keystore.active_public_jwks()}


@app.get("/jwks")
def get_jwks() -> Dict[str, Any]:
    """Alias JWKS endpoint."""
    return {"keys": keystore.active_public_jwks()}


def _sign_jwt_with(managed: ManagedKey, claims: Dict[str, Any]) -> str:
    """Helper to sign a JWT with RS256 and include the key id (kid) in the header."""
    token = jwt.JWT(header={"alg": "RS256", "kid": managed.kid}, claims=claims)
    token.make_signed_token(managed.key)
    return token.serialize()


# ---------------------------------------------------------------------------
# User registration
# ---------------------------------------------------------------------------


class RegisterRequest(BaseModel):
    username: str
    email: str


@app.post("/register", status_code=status.HTTP_201_CREATED)
def register_user(payload: RegisterRequest):
    """Create a user with a random password and return it once."""
    import sqlite3

    try:
        password = create_user(payload.username, payload.email)
    except sqlite3.IntegrityError:
        # Username or email already exists.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User already exists",
        )

    return {"password": password}


# ---------------------------------------------------------------------------
# Authentication endpoint
# ---------------------------------------------------------------------------


@app.post("/auth")
async def issue_token(
    request: Request,
    expired: bool = Query(
        default=False,
        description="If true, return an already-expired JWT using the expired key.",
    ),
):
    client_ip = request.client.host if request.client else "unknown"

    # Rate limit all /auth requests
    if _rate_limited(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too Many Requests",
        )

    now = int(time.time())
    subject = "fake-user"
    user_id: Optional[int] = None

    # Try to parse any JSON body, but treat failures as "no credentials"
    body: Optional[Dict[str, Any]] = None
    try:
        body = await request.json()
        if not isinstance(body, dict):
            body = None
    except Exception:
        body = None

    # If username + password are given, verify against DB
    if body is not None and "username" in body and "password" in body:
        username = str(body["username"])
        password = str(body["password"])
        user_id = verify_user_credentials(username, password)
        if user_id is None:
            # Invalid credentials: no token, no log
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password",
            )
        subject = username

    # Choose key and expiry based on "expired" flag
    if expired:
        mk = keystore.find_by_kid("expired-key")
        if mk is None:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Expired key missing",
            )
        claims = {"sub": subject, "iat": now - 120, "exp": now - 60}
    else:
        mk = keystore.get_latest_active()
        if mk is None:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="No active key available",
            )
        claims = {"sub": subject, "iat": now, "exp": now + 10 * 60}

    token = _sign_jwt_with(mk, claims)

    # Log only successful authentications
    log_auth_success(client_ip, user_id)

    return {"token": token}

