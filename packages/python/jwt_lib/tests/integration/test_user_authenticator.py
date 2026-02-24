"""Integration tests for the user authenticator."""

from __future__ import annotations

import time
from typing import Callable

import pytest

from jwt_lib.src.authenticator import UserAuthenticator
from jwt_lib.src.claims import TrustedClaims
from jwt_lib.src.exceptions import ExpiredTokenError
from jwt_lib.tests.conftest import create_token

USER_TOKEN_TYPE = "UserAuthToken"
USER_PRINCIPAL_TYPE = "USER"
USER_CONNECTION_METHOD = "UIDPWD"


@pytest.fixture
def user_token_factory(base_claims, private_key_pem: bytes) -> Callable[[dict | None], str]:
    """Create user tokens with optional claim overrides."""

    def _factory(overrides: dict | None = None) -> str:
        claims = base_claims.copy()
        claims.setdefault("tokenType", USER_TOKEN_TYPE)
        claims.setdefault("principalType", USER_PRINCIPAL_TYPE)
        claims.setdefault("connectionMethod", USER_CONNECTION_METHOD)
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
    ("scenario", "override_factory", "expected_exception"),
    [
        ("valid", lambda: {}, None),
        ("expired", lambda: {"exp": int(time.time()) - 60}, ExpiredTokenError),
    ],
    ids=["valid", "expired"],
)
async def test_user_authenticator_end_to_end(
    scenario: str,
    override_factory: Callable[[], dict],
    expected_exception,
    test_issuer: str,
    test_audience: str,
    user_token_factory,
    jwks_host,
):
    jwks_base_url, _ = jwks_host

    token = user_token_factory(override_factory())
    authenticator = UserAuthenticator(
        issuer=test_issuer,
        jwks_host=jwks_base_url,
        audience=test_audience,
    )

    if expected_exception:
        with pytest.raises(expected_exception):
            await authenticator.validate(token)
    else:
        claims = await authenticator.validate(token)
        assert isinstance(claims, TrustedClaims)
        assert claims.subject == "user123"
