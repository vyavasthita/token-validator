"""Additional integration tests for Auth0Authenticator."""

from __future__ import annotations

import time

import pytest

from jwt_lib.authenticator import Auth0Authenticator
from jwt_lib.exceptions import InvalidClaimError
from tests.conftest import create_token


@pytest.mark.asyncio
async def test_auth0_authenticator_rejects_wrong_grant_type(
    test_issuer: str,
    test_audience: str,
    private_key_pem: bytes,
    jwks_host,
):
    jwks_base_url, _ = jwks_host
    now = int(time.time())
    claims = {
        "iss": test_issuer,
        "aud": test_audience,
        "sub": "client@clients",
        "exp": now + 1800,
        "scope": "read:models",
        "gty": "authorization_code",
        "appName": "svc-app",
    }

    token = create_token(
        claims,
        private_key_pem,
        headers={"kid": "test-key-1", "typ": "JWT"},
    )

    authenticator = Auth0Authenticator(
        issuer=test_issuer,
        jwks_host=jwks_base_url,
        audience=test_audience,
        profile_kwargs={"app_name": "svc-app"},
    )

    with pytest.raises(InvalidClaimError):
        await authenticator.validate(token)


@pytest.mark.asyncio
async def test_auth0_authenticator_accepts_without_audience_when_not_configured(
    test_issuer: str,
    private_key_pem: bytes,
    jwks_host,
):
    jwks_base_url, _ = jwks_host
    now = int(time.time())
    claims = {
        "iss": test_issuer,
        "sub": "client@clients",
        "exp": now + 1800,
        "scope": "read:models",
        "gty": "client-credentials",
        "appName": "svc-app",
    }

    token = create_token(
        claims,
        private_key_pem,
        headers={"kid": "test-key-1", "typ": "JWT"},
    )

    authenticator = Auth0Authenticator(
        issuer=test_issuer,
        jwks_host=jwks_base_url,
        audience=None,
        profile_kwargs={"app_name": "svc-app"},
    )

    claims_obj = await authenticator.validate(token)
    assert claims_obj["sub"] == "client@clients"
