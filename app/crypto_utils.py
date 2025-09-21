from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, Any
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def b64url_nopad(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def gen_rsa_keypair(key_size: int = 2048) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


def public_numbers_to_jwk(pub: rsa.RSAPublicKey, kid: str) -> Dict[str, Any]:
    numbers = pub.public_numbers()
    n = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
    e = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": b64url_nopad(n),
        "e": b64url_nopad(e),
    }


def jwk_to_public_key(jwk: Dict[str, Any]) -> rsa.RSAPublicKey:
    n = int.from_bytes(base64.urlsafe_b64decode(jwk["n"] + "=="), "big")
    e = int.from_bytes(base64.urlsafe_b64decode(jwk["e"] + "=="), "big")
    return rsa.RSAPublicNumbers(e, n).public_key()


@dataclass(frozen=True)
class KeyRecord:
    kid: str
    private_key: rsa.RSAPrivateKey
    expires_at: datetime  # UTC


def new_kid() -> str:
    return uuid4().hex


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def minutes_from_now(m: int) -> datetime:
    return now_utc() + timedelta(minutes=m)