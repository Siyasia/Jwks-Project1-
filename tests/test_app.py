import os
import base64
import json
import time
from typing import Dict

import pytest
from fastapi.testclient import TestClient

# Make sure NOT_MY_KEY exists for tests before app imports keystore
os.environ.setdefault("NOT_MY_KEY", "test-secret-key-for-unit-tests-123")

from app.main import app  # noqa: E402  (import after setting env var)

client = TestClient(app)


def _decode_jwt_header(token: str) -> Dict:
    """Decode the first segment (header) of a JWT into a dict."""
    header_b64 = token.split(".")[0]
    pad = "=" * (-len(header_b64) % 4)
    return json.loads(base64.urlsafe_b64decode(header_b64 + pad))


def _decode_jwt_claims(token: str) -> Dict:
    """Decode the second segment (claims) of a JWT into a dict."""
    body_b64 = token.split(".")[1]
    pad = "=" * (-len(body_b64) % 4)
    return json.loads(base64.urlsafe_b64decode(body_b64 + pad))


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """
    Clear any in-memory rate-limiter state between tests (if present).
    """
    try:
        from app import main as app_main  # type: ignore
        rate_buckets = getattr(app_main, "_rate_buckets", None)
        rate_lock = getattr(app_main, "_rate_lock", None)
        if rate_buckets is not None and rate_lock is not None:
            with rate_lock:
                rate_buckets.clear()
    except Exception:
        # If the app doesn't implement a rate limiter, ignore.
        pass
    yield


# ---------------------------------------------------------------------------
# Basic JWKS behaviour
# ---------------------------------------------------------------------------


def test_well_known_jwks_returns_keys():
    r = client.get("/.well-known/jwks.json")
    assert r.status_code == 200
    data = r.json()
    assert "keys" in data
    assert isinstance(data["keys"], list)
    # there should be at least one active key
    assert len(data["keys"]) >= 1
    for key in data["keys"]:
        assert "kid" in key
        assert "kty" in key  # RSA, etc.


def test_jwks_alias_matches_well_known():
    r1 = client.get("/.well-known/jwks.json")
    r2 = client.get("/jwks")
    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r1.json() == r2.json()


def test_jwks_excludes_expired_key_from_expired_token():
    # Ask for an expired token and get the kid from its header
    r_token = client.post("/auth", params={"expired": 1})
    assert r_token.status_code == 200
    token = r_token.json()["token"]
    header = _decode_jwt_header(token)
    expired_kid = header["kid"]

    # JWKS should NOT include that expired key
    jwks = client.get("/.well-known/jwks.json").json()
    kids = {k["kid"] for k in jwks["keys"]}
    assert expired_kid not in kids


# ---------------------------------------------------------------------------
# /auth behaviour (JWT contents, expired flag, methods)
# ---------------------------------------------------------------------------


def test_auth_returns_jwt_signed_with_active_kid():
    r = client.post("/auth")
    assert r.status_code == 200
    data = r.json()
    assert "token" in data
    token = data["token"]

    header = _decode_jwt_header(token)
    assert header.get("alg") == "RS256"
    assert "kid" in header

    # active kid should appear in JWKS
    jwks = client.get("/.well-known/jwks.json").json()
    kids = {k["kid"] for k in jwks["keys"]}
    assert header["kid"] in kids


def test_auth_with_expired_flag_returns_past_exp():
    r = client.post("/auth", params={"expired": 1})
    assert r.status_code == 200
    token = r.json()["token"]

    claims = _decode_jwt_claims(token)
    assert "exp" in claims
    # exp should be strictly in the past
    assert claims["exp"] < int(time.time())


def test_auth_rejects_get_method():
    r = client.get("/auth")
    assert r.status_code == 405  # Method Not Allowed


def test_jwks_rejects_post_method():
    r = client.post("/jwks")
    assert r.status_code == 405


# ---------------------------------------------------------------------------
# User registration + credential-based auth
# ---------------------------------------------------------------------------


def test_register_creates_user_and_returns_password():
    username = "testuser_register"
    email = "testuser_register@example.com"

    r = client.post(
        "/register",
        json={"username": username, "email": email},
    )

    # Assignment allows 200 OK or 201 Created
    assert r.status_code in (200, 201)
    body = r.json()
    assert "password" in body
    assert isinstance(body["password"], str)
    assert len(body["password"]) > 0


def test_auth_with_username_password_issues_token_with_sub():
    username = "authuser1"
    email = "authuser1@example.com"

    # Register user
    r_reg = client.post(
        "/register",
        json={"username": username, "email": email},
    )
    assert r_reg.status_code in (200, 201)
    password = r_reg.json()["password"]

    # Authenticate with returned password
    r_auth = client.post(
        "/auth",
        json={"username": username, "password": password},
    )
    assert r_auth.status_code == 200
    token = r_auth.json()["token"]

    claims = _decode_jwt_claims(token)
    # Authenticated JWT should have sub set to username
    assert claims.get("sub") == username


def test_register_duplicate_username_fails():
    username = "duplicate_user"
    email1 = "dupe1@example.com"
    email2 = "dupe2@example.com"

    # First attempt may succeed (fresh DB) or already exist from previous runs.
    r1 = client.post(
        "/register",
        json={"username": username, "email": email1},
    )
    assert r1.status_code in (200, 201, 400, 409)

    # Second attempt *must* fail because username is already taken.
    r2 = client.post(
        "/register",
        json={"username": username, "email": email2},
    )
    assert r2.status_code in (400, 409)


# ---------------------------------------------------------------------------
# Rate limiter behaviour (optional bonus)
# ---------------------------------------------------------------------------


def test_auth_is_rate_limited_after_ten_requests_per_second():
    # Make a burst of /auth calls with no credentials.
    statuses = []
    for _ in range(12):
        r = client.post("/auth")
        statuses.append(r.status_code)

    # If rate limiting is implemented, we should see a 429;
    # otherwise, mark this as xfail instead of a hard failure.
    if not any(s == 429 for s in statuses):
        pytest.xfail(
            "Rate limiter not implemented or not enforcing 429 responses yet."
        )

    assert any(s == 429 for s in statuses)
