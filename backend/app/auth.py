"""
Cognito JWT verification, and the one role distinction the API makes.

Every data route requires a valid access token issued by the CloudSentinel
Cognito user pool. Verification is done locally against the pool's public JWKS:
signature, issuer, audience (client id), token_use and expiry are all checked.

Frontend-only auth would be theatre — without this, the endpoints could be
reached directly with curl. This is the enforcement point.

Two roles, two Cognito groups. Every operator can read what the console shows;
only a member of the approvers group can resume or stop a remediation. The
group is read from the token's claims, which Cognito fills from the pool's
membership when it issues the token, so an analyst cannot grant it to
themselves and the console's hiding of the buttons is not what enforces it.
"""
import logging
import math
import os
from functools import lru_cache

import requests
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from jwt import PyJWK, PyJWTError

from app.ratelimit import limiter

logger = logging.getLogger("cloudsentinel.auth")

REGION = os.environ.get("AWS_REGION", "us-east-1")
USER_POOL_ID = os.environ.get("COGNITO_USER_POOL_ID", "")
CLIENT_ID = os.environ.get("COGNITO_CLIENT_ID", "")
AUTH_ENABLED = os.environ.get("AUTH_ENABLED", "true").lower() == "true"
# The Cognito group whose members may decide approvals; the Auth stack creates
# it and the API stack names it, so the two cannot drift apart unnoticed.
APPROVERS_GROUP = os.environ.get("APPROVERS_GROUP", "approvers")

ISSUER = f"https://cognito-idp.{REGION}.amazonaws.com/{USER_POOL_ID}"
JWKS_URL = f"{ISSUER}/.well-known/jwks.json"

bearer = HTTPBearer(auto_error=False)


@lru_cache(maxsize=1)
def _jwks():
    """Cognito's public signing keys. Cached — they rotate rarely."""
    resp = requests.get(JWKS_URL, timeout=5)
    resp.raise_for_status()
    return resp.json()


def _unauthorized(detail: str):
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def require_auth(creds: HTTPAuthorizationCredentials = Depends(bearer)) -> dict:
    """FastAPI dependency: verify the bearer token, or reject with 401."""
    if not AUTH_ENABLED:
        return {"sub": "auth-disabled"}

    if creds is None or not creds.credentials:
        raise _unauthorized("missing bearer token")

    token = creds.credentials
    try:
        headers = jwt.get_unverified_header(token)
    except PyJWTError as e:
        raise _unauthorized(f"malformed token: {e}")

    try:
        kid = headers.get("kid")
        key = next((k for k in _jwks()["keys"] if k["kid"] == kid), None)
        if key is None:
            _jwks.cache_clear()  # keys may have rotated; retry once
            key = next((k for k in _jwks()["keys"] if k["kid"] == kid), None)
        if key is None:
            raise _unauthorized("unknown signing key")

        # The published key as an RSA key object, never as raw bytes: PyJWT
        # will not use an asymmetric key as an HMAC secret, and RS256 is the
        # only algorithm accepted, so a token signed with the public key
        # itself is refused twice over (tests/test_auth.py pins it).
        claims = jwt.decode(
            token,
            PyJWK(key, algorithm="RS256").key,
            algorithms=["RS256"],
            issuer=ISSUER,
            options={"verify_aud": False,  # access tokens carry client_id, not aud
                     "require": ["exp", "iss"]},
        )
    except PyJWTError as e:
        raise _unauthorized(f"invalid token: {e}")
    except requests.RequestException as e:
        # Fail closed: if the signing keys cannot be retrieved we deny access
        # rather than returning a server error.
        raise _unauthorized(f"unable to verify token: {e}")

    if claims.get("token_use") != "access":
        raise _unauthorized("wrong token type")
    if claims.get("client_id") != CLIENT_ID:
        raise _unauthorized("token not issued for this client")

    _throttle(claims)
    return claims


def _throttle(claims: dict) -> None:
    """The per-user limit (app.ratelimit), applied once the token is verified
    so that it counts identities, not whatever a caller claims to be. A
    refused request costs the caller a 429 and the API nothing further."""
    principal = claims.get("sub") or claims.get("username") or "unknown"
    wait = limiter.hit(principal)
    if wait is not None:
        logger.warning("RATE_LIMITED sub=%s retry_after=%d", principal, math.ceil(wait))
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"rate limit: {limiter.limit} requests a minute per user",
            headers={"Retry-After": str(max(1, math.ceil(wait)))},
        )


def groups_of(claims: dict) -> set:
    """The Cognito groups a verified token carries. Cognito writes them as a
    list under cognito:groups when it issues the token; a token issued before
    the user joined a group lacks it until the token is refreshed, and one
    issued before they left a group keeps it until expiry (an hour)."""
    found = claims.get("cognito:groups") or []
    if isinstance(found, str):
        found = [found]
    return {str(g) for g in found}


def require_approver(claims: dict = Depends(require_auth)) -> dict:
    """FastAPI dependency: a verified token whose user is in the approvers
    group, or 403. Reading never needs it; deciding an approval always does.
    It builds on require_auth, so an unauthenticated caller still gets 401
    and never learns that a group exists."""
    if not AUTH_ENABLED:
        return claims
    if APPROVERS_GROUP not in groups_of(claims):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"deciding an approval requires membership of the {APPROVERS_GROUP} group",
        )
    return claims
