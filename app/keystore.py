from __future__ import annotations
import time
from dataclasses import dataclass
from typing import Dict, List, Optional
from jwcrypto import jwk


@dataclass
class ManagedKey:
    kid: str
    key: jwk.JWK
    expires_at: int  # epoch seconds

    def public_jwk_dict(self) -> Dict:
        # export_public(as_dict=True) returns a dict (kty, n, e)
        data = self.key.export_public(as_dict=True)
        data["kid"] = self.kid
        data["alg"] = "RS256"
        data["use"] = "sig"
        return data


class KeyStore:
    def __init__(self) -> None:
        self._keys: Dict[str, ManagedKey] = {}

    def create_active_key(self, kid: str, ttl_seconds: int) -> ManagedKey:
        k = jwk.JWK.generate(kty="RSA", size=2048, kid=kid)
        mk = ManagedKey(kid=kid, key=k, expires_at=int(time.time()) + ttl_seconds)
        self._keys[kid] = mk
        return mk

    def create_expired_key(self, kid: str, seconds_ago: int = 60) -> ManagedKey:
        k = jwk.JWK.generate(kty="RSA", size=2048, kid=kid)
        mk = ManagedKey(kid=kid, key=k, expires_at=int(time.time()) - seconds_ago)
        self._keys[kid] = mk
        return mk

    def find_by_kid(self, kid: str) -> Optional[ManagedKey]:
        return self._keys.get(kid)

    def get_latest_active(self) -> Optional[ManagedKey]:
        now = int(time.time())
        actives = [mk for mk in self._keys.values() if mk.expires_at > now]
        if not actives:
            return None
        return sorted(actives, key=lambda m: m.expires_at, reverse=True)[0]

    def active_public_jwks(self) -> List[Dict]:
        now = int(time.time())
        return [
            mk.public_jwk_dict() for mk in self._keys.values() if mk.expires_at > now
        ]


# Initialize one active and one expired key
keystore = KeyStore()
keystore.create_active_key("active-key", ttl_seconds=60 * 60)
keystore.create_expired_key("expired-key", seconds_ago=60)
