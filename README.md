# JWKS Server (FastAPI)

Tiny server for learning JWT/JWKS.

- `GET /jwks` → returns **only unexpired** public keys (with `kid`, `alg`, `use`)
- `POST /auth` → returns a **valid** JWT (RS256) with `kid` in the header
- `POST /auth?expired=1` → returns an **expired** JWT signed by an expired key

## Run (local)
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
uvicorn app.main:app --reload --port 8080

