"""
The per-user rate limit.

The WAF bounds an address; this bounds an identity, after the token has been
verified. What is pinned: the limit is exact at the boundary, the window
slides rather than resets, a refused request does not extend the caller's own
window, keys are independent, and the 429 the API returns names the limit
and carries a Retry-After the client can act on.
"""
import os
import sys
import time
from pathlib import Path

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from jose import jwk, jwt

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

os.environ.setdefault("AWS_REGION", "us-east-1")
os.environ.setdefault("COGNITO_USER_POOL_ID", "us-east-1_testpool")
os.environ.setdefault("COGNITO_CLIENT_ID", "test-client-id")
os.environ.setdefault("AUTH_ENABLED", "true")

from app import auth as auth_module  # noqa: E402
from app.ratelimit import SlidingWindow  # noqa: E402


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def test_the_limit_is_exact_at_the_boundary():
    clock = Clock()
    window = SlidingWindow(limit=3, window=60, clock=clock)
    assert [window.hit("u") for _ in range(3)] == [None, None, None]
    assert window.hit("u") == pytest.approx(60.0)


def test_the_window_slides_and_a_refusal_says_when_to_retry():
    clock = Clock()
    window = SlidingWindow(limit=2, window=60, clock=clock)
    window.hit("u")
    clock.now += 10
    window.hit("u")
    clock.now += 10
    # The oldest hit was 20 s ago: 40 s until it leaves the window.
    assert window.hit("u") == pytest.approx(40.0)
    clock.now += 40
    assert window.hit("u") is None


def test_a_refused_request_does_not_extend_the_callers_own_window():
    clock = Clock()
    window = SlidingWindow(limit=1, window=60, clock=clock)
    window.hit("u")
    for _ in range(5):
        clock.now += 5
        assert window.hit("u") is not None
    clock.now += 35   # 60 s after the one counted hit
    assert window.hit("u") is None


def test_keys_are_independent():
    window = SlidingWindow(limit=1, window=60, clock=Clock())
    assert window.hit("a") is None
    assert window.hit("b") is None
    assert window.hit("a") is not None


def test_forget_clears_one_key():
    window = SlidingWindow(limit=1, window=60, clock=Clock())
    window.hit("a")
    window.forget("a")
    assert window.hit("a") is None


# ------------------------------------------------------------ through the API
def _rsa():
    """A real RSA key pair, as a JWKS entry and a signing PEM, so that the
    positive path of token verification is exercised rather than stubbed."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(serialization.Encoding.PEM,
                                    serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()).decode()
    public_pem = key.public_key().public_bytes(serialization.Encoding.PEM,
                                               serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    public = jwk.construct(public_pem, algorithm="RS256").to_dict()
    public["kid"] = "test-kid"
    return private_pem, {"keys": [public]}


def _stub_jwks(payload):
    def _fn():
        return payload
    _fn.cache_clear = lambda: None
    return _fn


def _token(private_pem, sub="operator-1"):
    claims = {"sub": sub, "token_use": "access", "client_id": "test-client-id",
              "iss": auth_module.ISSUER, "exp": int(time.time()) + 3600,
              "cognito:groups": ["approvers"]}
    return jwt.encode(claims, private_pem, algorithm="RS256", headers={"kid": "test-kid"})


def test_a_verified_caller_over_the_limit_gets_429_with_retry_after(monkeypatch):
    private_pem, jwks = _rsa()
    monkeypatch.setattr(auth_module, "_jwks", _stub_jwks(jwks))
    clock = Clock()
    monkeypatch.setattr(auth_module, "limiter", SlidingWindow(limit=2, window=60, clock=clock))
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=_token(private_pem))

    assert auth_module.require_auth(creds)["sub"] == "operator-1"
    assert auth_module.require_auth(creds)["sub"] == "operator-1"
    with pytest.raises(HTTPException) as exc:
        auth_module.require_auth(creds)
    assert exc.value.status_code == 429
    assert "120" not in exc.value.detail and "2 requests a minute" in exc.value.detail
    assert exc.value.headers["Retry-After"] == "60"

    clock.now += 60
    assert auth_module.require_auth(creds)["sub"] == "operator-1"


def test_the_limit_counts_identities_not_tokens(monkeypatch):
    """Two tokens for one user share a window; a second user has their own."""
    private_pem, jwks = _rsa()
    monkeypatch.setattr(auth_module, "_jwks", _stub_jwks(jwks))
    monkeypatch.setattr(auth_module, "limiter", SlidingWindow(limit=1, window=60, clock=Clock()))
    first = HTTPAuthorizationCredentials(scheme="Bearer", credentials=_token(private_pem, "u1"))
    again = HTTPAuthorizationCredentials(scheme="Bearer", credentials=_token(private_pem, "u1"))
    other = HTTPAuthorizationCredentials(scheme="Bearer", credentials=_token(private_pem, "u2"))
    auth_module.require_auth(first)
    with pytest.raises(HTTPException) as exc:
        auth_module.require_auth(again)
    assert exc.value.status_code == 429
    assert auth_module.require_auth(other)["sub"] == "u2"


def test_an_unverified_caller_never_reaches_the_limiter(monkeypatch):
    """The limit is per identity; a caller with no valid token is a 401, not
    a counted request, so forged subjects cannot exhaust a real user's window."""
    monkeypatch.setattr(auth_module, "_jwks", _stub_jwks({"keys": []}))
    counted = []
    limiter = SlidingWindow(limit=1, window=60, clock=Clock())
    original = limiter.hit
    limiter.hit = lambda key: counted.append(key) or original(key)
    monkeypatch.setattr(auth_module, "limiter", limiter)
    with pytest.raises(HTTPException) as exc:
        auth_module.require_auth(HTTPAuthorizationCredentials(scheme="Bearer", credentials="not-a-jwt"))
    assert exc.value.status_code == 401
    assert counted == []


def test_the_default_limit_is_well_above_the_consoles_polling():
    """The console polls five routes every thirty seconds: ten requests a
    minute. The default must leave room for a refresh-happy operator."""
    from app import ratelimit
    assert ratelimit.LIMIT_PER_MINUTE >= 60
