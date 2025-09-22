# JWKS Demo (FastAPI)

## Endpoints
- `GET /jwks` → JWKS with only **unexpired** public keys (includes `kid`, `alg`, `use`).
- `POST /auth` → Returns an **unexpired** JWT (RS256) with `kid` in header.
- `POST /auth?expired=1` → Returns an **expired** JWT signed by the **expired** key.

### Why `kid`?
Verifiers use the JWT header `kid` to pick the correct JWK from `/jwks`.

## Run
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
uvicorn app.main:app --reload --port 8080

