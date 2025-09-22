import base64, json, time
from typing import Dict
from fastapi.testclient import TestClient
from jwcrypto import jwk, jwt
from app.main import app

client = TestClient(app)


def _jwt_header(token: str) -> Dict:
    h = token.split(".")[0]
    pad = "=" * (-len(h) % 4)
    return json.loads(base64.urlsafe_b64decode(h + pad))


def test_jwks_excludes_expired():
    r = client.get("/jwks")
    r.raise_for_status()
    kids = [k["kid"] for k in r.json()["keys"]]
    assert "active-key" in kids
    assert "expired-key" not in kids


def test_auth_returns_valid_unexpired_jwt():
    r = client.post("/auth")
    r.raise_for_status()
    token = r.json()["token"]

    jwks = client.get("/jwks").json()
    kid = _jwt_header(token)["kid"]
    pub_jwk_dict = next(k for k in jwks["keys"] if k["kid"] == kid)

    pub = jwk.JWK.from_json(json.dumps(pub_jwk_dict))
    verified = jwt.JWT(key=pub, jwt=token)  # verifies signature
    claims = json.loads(verified.claims)
    assert claims["sub"] == "fake-user"
    assert claims["exp"] > int(time.time())


def test_auth_returns_expired_jwt_on_query_param():
    r = client.post("/auth?expired=1")
    r.raise_for_status()
    token = r.json()["token"]

    # Header kid should be expired-key
    assert _jwt_header(token)["kid"] == "expired-key"

    # Decode body to assert exp is in the past
    body_b64 = token.split(".")[1]
    pad = "=" * (-len(body_b64) % 4)
    claims = json.loads(base64.urlsafe_b64decode(body_b64 + pad))
    assert claims["exp"] < int(time.time())
