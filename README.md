# Basic JWKS Server (FastAPI)

**Author:** Ximena Armentero  
**Course:** CSCE 3550 — JWKS Assignment

## Endpoints
- `GET /.well-known/jwks.json` — JWKS for **unexpired** keys only  
- `POST /auth` — returns a JWT (RS256) with a `kid` header  
  - `POST /auth?expired=1` — returns an **expired** JWT signed by an **expired** key

## Run locally
```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -U pip
pip install -e '.[dev]'
uvicorn app.main:app --port 8080 --reload
