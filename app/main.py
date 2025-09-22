from __future__ import annotations
import time
from typing import Any, Dict
from fastapi import FastAPI, HTTPException, Query
from jwcrypto import jwt
from .keystore import keystore, ManagedKey

app = FastAPI(title="JWKS Demo", version="1.0.0")


@app.get("/jwks")
def get_jwks() -> Dict[str, Any]:
    """Return JWKS (only UNEXPIRED public keys)."""
    return {"keys": keystore.active_public_jwks()}


def _sign_jwt_with(managed: ManagedKey, claims: Dict[str, Any]) -> str:
    """Sign a JWT (RS256) with the given key and include the kid in the header."""
    token = jwt.JWT(header={"alg": "RS256", "kid": managed.kid}, claims=claims)
    token.make_signed_token(managed.key)
    return token.serialize()


@app.post("/auth")
def issue_token(expired: int = Query(default=0, ge=0, le=1)):
    """
    POST /auth
    - Normal: return a valid, unexpired JWT signed by latest active key.
    - If ?expired=1: return an already-expired JWT signed by the expired key.
    """
    now = int(time.time())

    if expired == 1:
        mk = keystore.find_by_kid("expired-key")
        if not mk:
            raise HTTPException(status_code=500, detail="Expired key missing")
        claims = {"sub": "fake-user", "iat": now - 120, "exp": now - 60}
        return {"token": _sign_jwt_with(mk, claims)}

    mk = keystore.get_latest_active()
    if not mk:
        raise HTTPException(status_code=500, detail="No active key available")
    claims = {"sub": "fake-user", "iat": now, "exp": now + 10 * 60}
    return {"token": _sign_jwt_with(mk, claims)}
