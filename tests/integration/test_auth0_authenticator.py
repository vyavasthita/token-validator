"""Integration tests for the Auth0 authenticator."""

from __future__ import annotations

import time
from typing import Callable

import pytest

from jwt_lib.authenticator import Auth0Authenticator
from jwt_lib.claims import TrustedClaims
from jwt_lib.exceptions import InvalidClaimError
from tests.conftest import create_token


@pytest.fixture
def auth0_base_claims(test_issuer: str, test_audience: str) -> dict:
    now = int(time.time())
    return {
        "iss": test_issuer,
        "aud": test_audience,
        "sub": "client@clients",
        "exp": now + 1800,
        "scope": "read:models write:models",
        "gty": "client-credentials",
        "azp": "svc-client",
        "appName": "svc-app",
    }


@pytest.fixture
def auth0_token_factory(auth0_base_claims: dict, private_key_pem: bytes) -> Callable[[dict | None], str]:
    def _factory(overrides: dict | None = None) -> str:
        claims = auth0_base_claims.copy()
        if overrides:
            claims.update(overrides)
        return create_token(
            claims,
            private_key_pem,
            headers={"kid": "test-key-1", "typ": "JWT"},
        )

    return _factory


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("scenario", "claim_overrides", "expected_exception"),
    [
        ("valid", {}, None),
        ("wrong_app", {"appName": "other"}, InvalidClaimError),
    ],
    ids=["valid", "wrong_app"],
)
async def test_auth0_authenticator_end_to_end(
    scenario: str,
    claim_overrides: dict,
    expected_exception,
    test_issuer: str,
    test_audience: str,
    auth0_token_factory,
    jwks_host,
):
    jwks_base_url, _ = jwks_host
    token = auth0_token_factory(claim_overrides)

    authenticator = Auth0Authenticator(
        issuer=test_issuer,
        jwks_host=jwks_base_url,
        audience=test_audience,
        profile_kwargs={"app_name": "svc-app"},
    )

    if expected_exception:
        with pytest.raises(expected_exception):
            await authenticator.validate(token)
    else:
        claims = await authenticator.validate(token)
        assert isinstance(claims, TrustedClaims)
        assert claims["appName"] == "svc-app"
