"""Tests for the user JWT verifier."""

import time
from typing import Any
from unittest.mock import MagicMock

import pytest
from jwt import PyJWKClient

from jwt_lib.src.claims import TrustedClaims
from jwt_lib.src.exceptions import InvalidClaimError
from jwt_lib.src.verifier import UserJWTVerifier
from jwt_lib.tests.conftest import create_token


class TestUserJWTVerifier:
    """UserJWTVerifier enforces stricter JOSE + temporal policies."""

    def _user_headers(self, **overrides: Any) -> dict[str, Any]:
        headers = {"kid": "test-key-1", "typ": "JWT"}
        for key, value in overrides.items():
            if value is None:
                headers.pop(key, None)
            else:
                headers[key] = value
        return headers

    @pytest.mark.asyncio
    async def test_user_verifier_valid_token(
        self,
        test_issuer: str,
        test_audience: str,
        base_claims: dict,
        private_key_pem: bytes,
        rsa_key_pair,
    ):
        _, public_key = rsa_key_pair
        token = create_token(
            base_claims,
            private_key_pem,
            headers=self._user_headers(),
        )

        mock_signing_key = MagicMock()
        mock_signing_key.key = public_key
        mock_jwks_client = MagicMock(spec=PyJWKClient)
        mock_jwks_client.get_signing_key_from_jwt.return_value = mock_signing_key

        verifier = UserJWTVerifier(issuer=test_issuer, audience=test_audience)
        verifier._jwks_client = mock_jwks_client

        claims = await verifier.validate(token)
        assert isinstance(claims, TrustedClaims)
        assert claims.subject == base_claims["sub"]

    @pytest.mark.asyncio
    async def test_missing_kid_header_is_rejected(
        self,
        test_issuer: str,
        test_audience: str,
        base_claims: dict,
        private_key_pem: bytes,
        rsa_key_pair,
    ):
        _, public_key = rsa_key_pair
        token = create_token(
            base_claims,
            private_key_pem,
            headers=self._user_headers(kid=None),
        )

        mock_signing_key = MagicMock()
        mock_signing_key.key = public_key
        mock_jwks_client = MagicMock(spec=PyJWKClient)
        mock_jwks_client.get_signing_key_from_jwt.return_value = mock_signing_key

        verifier = UserJWTVerifier(issuer=test_issuer, audience=test_audience)
        verifier._jwks_client = mock_jwks_client

        with pytest.raises(InvalidClaimError, match="kid"):
            await verifier.validate(token)

    @pytest.mark.asyncio
    async def test_invalid_typ_header_is_rejected(
        self,
        test_issuer: str,
        test_audience: str,
        base_claims: dict,
        private_key_pem: bytes,
        rsa_key_pair,
    ):
        _, public_key = rsa_key_pair
        token = create_token(
            base_claims,
            private_key_pem,
            headers=self._user_headers(typ="WRONG"),
        )

        mock_signing_key = MagicMock()
        mock_signing_key.key = public_key
        mock_jwks_client = MagicMock(spec=PyJWKClient)
        mock_jwks_client.get_signing_key_from_jwt.return_value = mock_signing_key

        verifier = UserJWTVerifier(issuer=test_issuer, audience=test_audience)
        verifier._jwks_client = mock_jwks_client

        with pytest.raises(InvalidClaimError, match="typ"):
            await verifier.validate(token)

    @pytest.mark.asyncio
    async def test_future_iat_is_rejected(
        self,
        test_issuer: str,
        test_audience: str,
        base_claims: dict,
        private_key_pem: bytes,
        rsa_key_pair,
    ):
        _, public_key = rsa_key_pair
        claims = base_claims.copy()
        claims["iat"] = int(time.time()) + 300

        token = create_token(
            claims,
            private_key_pem,
            headers=self._user_headers(),
        )

        mock_signing_key = MagicMock()
        mock_signing_key.key = public_key
        mock_jwks_client = MagicMock(spec=PyJWKClient)
        mock_jwks_client.get_signing_key_from_jwt.return_value = mock_signing_key

        verifier = UserJWTVerifier(
            issuer=test_issuer,
            audience=test_audience,
            clock_skew_seconds=30,
        )
        verifier._jwks_client = mock_jwks_client

        with pytest.raises(InvalidClaimError, match="future"):
            await verifier.validate(token)

    @pytest.mark.asyncio
    async def test_missing_nbf_is_rejected(
        self,
        test_issuer: str,
        test_audience: str,
        base_claims: dict,
        private_key_pem: bytes,
        rsa_key_pair,
    ):
        _, public_key = rsa_key_pair
        claims = base_claims.copy()
        claims.pop("nbf", None)

        token = create_token(
            claims,
            private_key_pem,
            headers=self._user_headers(),
        )

        mock_signing_key = MagicMock()
        mock_signing_key.key = public_key
        mock_jwks_client = MagicMock(spec=PyJWKClient)
        mock_jwks_client.get_signing_key_from_jwt.return_value = mock_signing_key

        verifier = UserJWTVerifier(issuer=test_issuer, audience=test_audience)
        verifier._jwks_client = mock_jwks_client

        with pytest.raises(InvalidClaimError, match="nbf"):
            await verifier.validate(token)

    @pytest.mark.asyncio
    async def test_max_token_age_enforced(
        self,
        test_issuer: str,
        test_audience: str,
        base_claims: dict,
        private_key_pem: bytes,
        rsa_key_pair,
    ):
        _, public_key = rsa_key_pair
        now = int(time.time())
        claims = base_claims.copy()
        claims["iat"] = now - 7200
        claims["nbf"] = now - 7200
        claims["exp"] = now + 600

        token = create_token(
            claims,
            private_key_pem,
            headers=self._user_headers(),
        )

        mock_signing_key = MagicMock()
        mock_signing_key.key = public_key
        mock_jwks_client = MagicMock(spec=PyJWKClient)
        mock_jwks_client.get_signing_key_from_jwt.return_value = mock_signing_key

        verifier = UserJWTVerifier(
            issuer=test_issuer,
            audience=test_audience,
            max_token_age_seconds=60,
        )
        verifier._jwks_client = mock_jwks_client

        with pytest.raises(InvalidClaimError, match="maximum allowed age"):
            await verifier.validate(token)
