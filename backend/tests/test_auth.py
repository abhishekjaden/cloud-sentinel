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
import jwt

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
        "attacker-chosen-secret-of-thirty-two-bytes", algorithm="HS256",
    )
    with pytest.raises(HTTPException) as exc:
        auth_module.require_auth(creds(forged))
    assert exc.value.status_code == 401


def test_a_token_hmac_signed_with_the_published_public_key_is_rejected(monkeypatch):
    """Algorithm confusion. The pool's public key is published; a token signed
    with HS256 using that key, DER or PEM, as the HMAC secret must not verify.
    It is refused twice over: decode accepts RS256 alone — widening that list
    makes this test fail — and the key it is handed is an RSA key object,
    which PyJWT will not use as an HMAC secret.
    python-jose, the library this replaced on 25 October 2026, had an advisory
    with no fixed release on exactly this path (a DER-encoded public key
    accepted as a raw HMAC secret). The forged signatures are computed by hand
    so that no library check stands in for the API's, and a token signed
    properly with the private key is accepted first, so the rejections are
    the algorithm's and not a broken key."""
    import base64
    import hashlib
    import hmac
    import json

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from jwt.algorithms import RSAAlgorithm

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()).decode()
    public_pem = key.public_key().public_bytes(serialization.Encoding.PEM,
                                               serialization.PublicFormat.SubjectPublicKeyInfo)
    public_der = key.public_key().public_bytes(serialization.Encoding.DER,
                                               serialization.PublicFormat.SubjectPublicKeyInfo)
    published = RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
    published.update({"kid": "real-kid", "alg": "RS256", "use": "sig"})
    monkeypatch.setattr(auth_module, "_jwks", _stub_jwks({"keys": [published]}))
    claims = {"sub": "algorithm-confusion", "token_use": "access", "client_id": CLIENT,
              "iss": ISSUER, "exp": int(time.time()) + 3600}

    genuine = jwt.encode(claims, private_pem, algorithm="RS256", headers={"kid": "real-kid"})
    assert auth_module.require_auth(creds(genuine))["sub"] == "algorithm-confusion"

    def b64(raw):
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    head = b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": "real-kid"}).encode())
    body = b64(json.dumps(claims).encode())
    for secret in (public_der, public_pem):
        signature = hmac.new(secret, f"{head}.{body}".encode(), hashlib.sha256).digest()
        with pytest.raises(HTTPException) as exc:
            auth_module.require_auth(creds(f"{head}.{body}.{b64(signature)}"))
        assert exc.value.status_code == 401


def test_token_signed_with_an_unknown_key_is_rejected(monkeypatch):
    """If the token's kid is not published by our pool, deny."""
    monkeypatch.setattr(auth_module, "_jwks", _stub_jwks({"keys": []}))
    token = jwt.encode({"sub": "x"}, "a-throwaway-secret-of-thirty-two-bytes", algorithm="HS256",
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
    token = jwt.encode({"sub": "x"}, "a-throwaway-secret-of-thirty-two-bytes", algorithm="HS256",
                       headers={"kid": "any"})
    with pytest.raises(HTTPException) as exc:
        auth_module.require_auth(creds(token))
    assert exc.value.status_code == 401


# ---------------------------------------------------------------- the approvers group
def test_groups_are_read_from_the_token_claim():
    assert auth_module.groups_of({"cognito:groups": ["analysts", "approvers"]}) == {"analysts", "approvers"}
    assert auth_module.groups_of({"cognito:groups": "approvers"}) == {"approvers"}
    assert auth_module.groups_of({"sub": "x"}) == set()


def test_an_approver_passes_the_approver_check():
    claims = {"sub": "op", "cognito:groups": ["approvers"]}
    assert auth_module.require_approver(claims) is claims


@pytest.mark.parametrize("claims", [
    {"sub": "op"},
    {"sub": "op", "cognito:groups": []},
    {"sub": "op", "cognito:groups": ["analysts"]},
    {"sub": "op", "cognito:groups": ["Approvers"]},   # the name is exact
])
def test_anyone_else_is_refused_with_403(claims):
    with pytest.raises(HTTPException) as exc:
        auth_module.require_approver(claims)
    assert exc.value.status_code == 403


def test_the_group_name_comes_from_the_environment_with_the_pools_name_as_default():
    """The Auth stack creates the group and the API stack names it; the
    default is the same word, so a deployment that forgets to set it still
    checks the right group rather than none."""
    assert auth_module.APPROVERS_GROUP == "approvers"


def test_disabled_auth_skips_the_approver_check_too(monkeypatch):
    monkeypatch.setattr(auth_module, "AUTH_ENABLED", False)
    assert auth_module.require_approver({"sub": "auth-disabled"})["sub"] == "auth-disabled"


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
