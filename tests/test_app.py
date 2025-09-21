from __future__ import annotations

import jwt
import pytest
from fastapi.testclient import TestClient

from app.main import app, keystore
from app.crypto_utils import jwk_to_public_key

client = TestClient(app)


def test_jwks_shows_only_unexpired_key():
    r = client.get("/.well-known/jwks.json")
    assert r.status_code == 200
    data = r.json()
    kids = [k["kid"] for k in data["keys"]]
    assert keystore.current.kid in kids
    assert keystore.expired.kid not in kids


def test_auth_returns_valid_unexpired_token():
    r = client.post("/auth")
    assert r.status_code == 200
    body = r.json()
    assert body["expired"] is False
    token = body["token"]
    kid = body["kid"]
    # verify using JWKS public key
    jwks = client.get("/.well-known/jwks.json").json()
    target = next(k for k in jwks["keys"] if k["kid"] == kid)
    pub = jwk_to_public_key(target)
    decoded = jwt.decode(token, key=pub, algorithms=["RS256"], options={"require": ["exp", "iat", "sub"]})
    assert decoded["sub"] == "fake-user-123"


def test_auth_expired_param_mints_expired_token():
    r = client.post("/auth?expired=1")
    assert r.status_code == 200
    body = r.json()
    assert body["expired"] is True
    token = body["token"]
    kid = body["kid"]
    assert kid == keystore.expired.kid
    # expired token should raise on verification (use the expired key directly)
    with pytest.raises(jwt.ExpiredSignatureError):
        jwt.decode(
            token,
            key=keystore.expired.private_key.public_key(),
            algorithms=["RS256"],
            options={"require": ["exp", "iat", "sub"]},
        )