from __future__ import annotations

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware

from .keys import KeyStore

app = FastAPI(title="Basic JWKS Server", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

keystore = KeyStore.bootstrap(current_ttl_minutes=30, expired_minutes_ago=60)


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.get("/.well-known/jwks.json")
def jwks():
    """Return JWKS containing only unexpired keys."""
    return keystore.as_jwks()


@app.post("/auth")
def auth(expired: bool = Query(default=False, description="Use expired key and past exp if true")):
    """Return a signed JWT. If ?expired=1, sign with expired key and set exp in the past."""
    token, rec = keystore.build_jwt(use_expired=expired)
    return {"token": token, "kid": rec.kid, "expired": expired}