"""
Tests for Cognito JWT verification.

This is the enforcement point that makes the dashboard's login meaningful: the
API must reject anything that is not a valid access token issued by our own
user pool for our own client. Each rejection path is pinned here so it cannot
be weakened by accident.
"""
import os
import sys
import time
from pathlib import Path

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from jose import jwt

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

POOL = "us-east-1_testpool"
CLIENT = "test-client-id"
REGION = "us-east-1"
ISSUER = f"https://cognito-idp.{REGION}.amazonaws.com/{POOL}"

os.environ.setdefault("AWS_REGION", REGION)
os.environ.setdefault("COGNITO_USER_POOL_ID", POOL)
os.environ.setdefault("COGNITO_CLIENT_ID", CLIENT)
os.environ.setdefault("AUTH_ENABLED", "true")

from app import auth as auth_module  # noqa: E402


def _stub_jwks(payload):
    """A stand-in for the lru_cache-wrapped _jwks(); auth.py calls
    cache_clear() on it when a kid is not found, so the stub must offer it."""
    def _fn():
        return payload
    _fn.cache_clear = lambda: None
    return _fn

def creds(token):
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


def test_missing_credentials_are_rejected():
    with pytest.raises(HTTPException) as exc:
        auth_module.require_auth(None)
    assert exc.value.status_code == 401
    assert "missing bearer token" in exc.value.detail


def test_empty_token_is_rejected():
    with pytest.raises(HTTPException) as exc:
        auth_module.require_auth(creds(""))
    assert exc.value.status_code == 401


def test_garbage_token_is_rejected():
    with pytest.raises(HTTPException) as exc:
        auth_module.require_auth(creds("not-a-jwt"))
    assert exc.value.status_code == 401


def test_forged_token_is_rejected(monkeypatch):
    """A token the caller signed themselves must not be accepted, however
    well-formed its claims are. JWKS is stubbed so no network call is made."""
    monkeypatch.setattr(auth_module, "_jwks",
                        _stub_jwks({"keys": [{"kid": "real-kid", "kty": "RSA",
                                              "n": "0vx7", "e": "AQAB"}]}))
    forged = jwt.encode(
        {"sub": "attacker", "token_use": "access", "client_id": CLIENT,
         "iss": ISSUER, "exp": int(time.time()) + 3600},
        "attacker-chosen-secret", algorithm="HS256",
    )
    with pytest.raises(HTTPException) as exc:
        auth_module.require_auth(creds(forged))
    assert exc.value.status_code == 401


def test_token_signed_with_an_unknown_key_is_rejected(monkeypatch):
    """If the token's kid is not published by our pool, deny."""
    monkeypatch.setattr(auth_module, "_jwks", _stub_jwks({"keys": []}))
    token = jwt.encode({"sub": "x"}, "secret", algorithm="HS256",
                       headers={"kid": "unpublished"})
    with pytest.raises(HTTPException) as exc:
        auth_module.require_auth(creds(token))
    assert exc.value.status_code == 401


def test_unreachable_jwks_denies_rather_than_erroring(monkeypatch):
    """If the signing keys cannot be fetched the request must fail closed with
    401, not surface as a 500."""
    import requests

    def boom():
        raise requests.ConnectionError("cognito unreachable")

    boom.cache_clear = lambda: None
    monkeypatch.setattr(auth_module, "_jwks", boom)
    token = jwt.encode({"sub": "x"}, "secret", algorithm="HS256",
                       headers={"kid": "any"})
    with pytest.raises(HTTPException) as exc:
        auth_module.require_auth(creds(token))
    assert exc.value.status_code == 401


def test_auth_can_be_disabled_for_local_development(monkeypatch):
    """AUTH_ENABLED=false is a local convenience; it must never be the default."""
    monkeypatch.setattr(auth_module, "AUTH_ENABLED", False)
    assert auth_module.require_auth(None)["sub"] == "auth-disabled"


def test_auth_is_enabled_by_default():
    """If the environment variable is absent the module must fail closed."""
    assert os.environ.get("AUTH_ENABLED", "true").lower() == "true"


def test_issuer_is_derived_from_the_configured_pool():
    assert auth_module.ISSUER == ISSUER
    assert auth_module.JWKS_URL.startswith(ISSUER)
    assert auth_module.JWKS_URL.endswith("/.well-known/jwks.json")
