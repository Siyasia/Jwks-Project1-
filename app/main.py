from __future__ import annotations
import time
from typing import Any, Dict
from fastapi import FastAPI, HTTPException, Query
from jwcrypto import jwt
from .keystore import keystore, ManagedKey

# create the FastAPI app (shows title/version in /docs)
app = FastAPI(title="JWKS Demo", version="1.1.0")


# standard JWKS endpoint path used by many clients/graders
@app.get("/.well-known/jwks.json")
def get_well_known_jwks() -> Dict[str, Any]:
    # return JWKS containing ONLY unexpired public keys
    return {"keys": keystore.active_public_jwks()}


# keep your original /jwks path as an alias
@app.get("/jwks")
def get_jwks() -> Dict[str, Any]:
    # return JWKS containing ONLY unexpired public keys
    return {"keys": keystore.active_public_jwks()}


def _sign_jwt_with(managed: ManagedKey, claims: Dict[str, Any]) -> str:
    # sign a JWT with RS256 and include the key id (kid) in the header
    token = jwt.JWT(header={"alg": "RS256", "kid": managed.kid}, claims=claims)
    token.make_signed_token(managed.key)
    return token.serialize()


# issue a JWT, either valid or expired based on query param
@app.post("/auth")
def issue_token(
    # accept booleans like ?expired=true/false AND 1/0 for compatibility
    expired: bool = Query(default=False, description="Return an expired token if true"),
):
    now = int(time.time())  # epoch seconds

    if expired:
        # use the intentionally expired key for the assignment
        mk = keystore.find_by_kid("expired-key")
        if not mk:
            raise HTTPException(status_code=500, detail="Expired key missing")
        claims = {"sub": "fake-user", "iat": now - 120, "exp": now - 60}  # exp in the past
        return {"token": _sign_jwt_with(mk, claims)}

    # use the latest active key
    mk = keystore.get_latest_active()
    if not mk:
        raise HTTPException(status_code=500, detail="No active key available")

    # create a token valid for 10 minutes
    claims = {"sub": "fake-user", "iat": now, "exp": now + 10 * 60}
    return {"token": _sign_jwt_with(mk, claims)}

