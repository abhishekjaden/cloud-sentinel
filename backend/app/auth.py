"""
Cognito JWT verification.

Every data route requires a valid access token issued by the CloudSentinel
Cognito user pool. Verification is done locally against the pool's public JWKS:
signature, issuer, audience (client id), token_use and expiry are all checked.

Frontend-only auth would be theatre — without this, the endpoints could be
reached directly with curl. This is the enforcement point.
"""
import os
from functools import lru_cache

import requests
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError

REGION = os.environ.get("AWS_REGION", "us-east-1")
USER_POOL_ID = os.environ.get("COGNITO_USER_POOL_ID", "")
CLIENT_ID = os.environ.get("COGNITO_CLIENT_ID", "")
AUTH_ENABLED = os.environ.get("AUTH_ENABLED", "true").lower() == "true"

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
        kid = headers.get("kid")
        key = next((k for k in _jwks()["keys"] if k["kid"] == kid), None)
        if key is None:
            _jwks.cache_clear()  # keys may have rotated; retry once
            key = next((k for k in _jwks()["keys"] if k["kid"] == kid), None)
        if key is None:
            raise _unauthorized("unknown signing key")

        claims = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            issuer=ISSUER,
            options={"verify_aud": False},  # access tokens carry client_id, not aud
        )
    except JWTError as e:
        raise _unauthorized(f"invalid token: {e}")

    if claims.get("token_use") != "access":
        raise _unauthorized("wrong token type")
    if claims.get("client_id") != CLIENT_ID:
        raise _unauthorized("token not issued for this client")

    return claims
