"""Additional integration tests for UserAuthenticator."""

from __future__ import annotations

import pytest

from jwt_lib.authenticator import UserAuthenticator
from jwt_lib.exceptions import InvalidClaimError
from tests.conftest import create_token


@pytest.mark.asyncio
async def test_user_authenticator_rejects_missing_connection_method(
    test_issuer: str,
    test_audience: str,
    base_claims: dict,
    private_key_pem: bytes,
    jwks_host,
):
    jwks_base_url, _ = jwks_host
    claims = base_claims.copy()
    claims["tokenType"] = "UserAuthToken"
    claims["principalType"] = "USER"
    claims.pop("connectionMethod", None)

    token = create_token(
        claims,
        private_key_pem,
        headers={"kid": "test-key-1", "typ": "JWT"},
    )

    authenticator = UserAuthenticator(
        issuer=test_issuer,
        jwks_host=jwks_base_url,
        audience=test_audience,
    )

    with pytest.raises(InvalidClaimError):
        await authenticator.validate(token)


@pytest.mark.asyncio
async def test_user_authenticator_rejects_bad_principal_type(
    test_issuer: str,
    test_audience: str,
    base_claims: dict,
    private_key_pem: bytes,
    jwks_host,
):
    jwks_base_url, _ = jwks_host
    claims = base_claims.copy()
    claims["tokenType"] = "UserAuthToken"
    claims["principalType"] = "SERVICE"
    claims["connectionMethod"] = "UIDPWD"

    token = create_token(
        claims,
        private_key_pem,
        headers={"kid": "test-key-1", "typ": "JWT"},
    )

    authenticator = UserAuthenticator(
        issuer=test_issuer,
        jwks_host=jwks_base_url,
        audience=test_audience,
    )

    with pytest.raises(InvalidClaimError):
        await authenticator.validate(token)
