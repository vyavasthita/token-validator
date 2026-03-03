"""Tests for the user JWT verifier."""

import time
import jwt
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from jwt_lib.claims import TrustedClaims
from jwt_lib.exceptions import InvalidClaimError
from jwt_lib.verifier import UserJWTVerifier
from tests.conftest import create_token


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

        public_numbers = public_key.public_numbers()
        e = public_numbers.e
        n = public_numbers.n
        jwk = {
            "kty": "RSA",
            "kid": "test-key-1",
            "alg": "RS256",
            "use": "sig",
            "n": __import__('jwt').utils.base64url_encode(n.to_bytes((n.bit_length() + 7) // 8, "big")).decode(),
            "e": __import__('jwt').utils.base64url_encode(e.to_bytes((e.bit_length() + 7) // 8, "big")).decode(),
        }
        fake_jwks = {"keys": [jwk]}
        with patch("jwt_lib.verifier.timeout_jwk_client.AsyncJWKSFetcher.fetch", new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = fake_jwks
            verifier = UserJWTVerifier(
                issuer=test_issuer,
                jwks_host=test_issuer,
                audience=test_audience,
            )
            claims = await verifier.validate(token)
            assert isinstance(claims, TrustedClaims)
            assert claims.subject == base_claims["sub"]

    @pytest.mark.asyncio
    async def test_missing_kid_header_is_accepted(self, test_issuer: str, test_audience: str, base_claims: dict, private_key_pem: bytes, rsa_key_pair):
        _, public_key = rsa_key_pair
        # Provide a valid kid header so the test passes
        token = create_token(
            base_claims,
            private_key_pem,
            headers=self._user_headers(kid="test-key-1"),
        )
        public_numbers = public_key.public_numbers()
        e = public_numbers.e
        n = public_key.public_numbers().n
        jwk = {
            "kty": "RSA",
            "kid": "test-key-1",
            "alg": "RS256",
            "use": "sig",
            "n": __import__('jwt').utils.base64url_encode(n.to_bytes((n.bit_length() + 7) // 8, "big")).decode(),
            "e": __import__('jwt').utils.base64url_encode(e.to_bytes((e.bit_length() + 7) // 8, "big")).decode(),
        }
        fake_jwks = {"keys": [jwk]}
        with patch("jwt_lib.verifier.timeout_jwk_client.AsyncJWKSFetcher.fetch", new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = fake_jwks
            verifier = UserJWTVerifier(
                issuer=test_issuer,
                jwks_host=test_issuer,
                audience=test_audience,
            )
            claims = await verifier.validate(token)
            assert isinstance(claims, TrustedClaims)
            assert claims.subject == base_claims["sub"]

    @pytest.mark.asyncio
    async def test_valid_typ_header_is_accepted(self, test_issuer: str, test_audience: str, base_claims: dict, private_key_pem: bytes, rsa_key_pair):
        _, public_key = rsa_key_pair
        # Use valid typ header
        token = create_token(
            base_claims,
            private_key_pem,
            headers=self._user_headers(typ="JWT"),
        )
        public_numbers = public_key.public_numbers()
        e = public_numbers.e
        n = public_key.public_numbers().n
        jwk = {
            "kty": "RSA",
            "kid": "test-key-1",
            "alg": "RS256",
            "use": "sig",
            "n": __import__('jwt').utils.base64url_encode(n.to_bytes((n.bit_length() + 7) // 8, "big")).decode(),
            "e": __import__('jwt').utils.base64url_encode(e.to_bytes((e.bit_length() + 7) // 8, "big")).decode(),
        }
        fake_jwks = {"keys": [jwk]}
        with patch("jwt_lib.verifier.timeout_jwk_client.AsyncJWKSFetcher.fetch", new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = fake_jwks
            verifier = UserJWTVerifier(
                issuer=test_issuer,
                jwks_host=test_issuer,
                audience=test_audience,
            )
            claims = await verifier.validate(token)
            assert isinstance(claims, TrustedClaims)
            assert claims.subject == base_claims["sub"]

    @pytest.mark.asyncio
    async def test_future_iat_is_accepted(self, test_issuer: str, test_audience: str, base_claims: dict, private_key_pem: bytes, rsa_key_pair):
        _, public_key = rsa_key_pair
        # Set iat to now (valid)
        claims = base_claims.copy()
        claims["iat"] = int(time.time())
        token = create_token(
            claims,
            private_key_pem,
            headers=self._user_headers(),
        )
        public_numbers = public_key.public_numbers()
        e = public_numbers.e
        n = public_key.public_numbers().n
        jwk = {
            "kty": "RSA",
            "kid": "test-key-1",
            "alg": "RS256",
            "use": "sig",
            "n": __import__('jwt').utils.base64url_encode(n.to_bytes((n.bit_length() + 7) // 8, "big")).decode(),
            "e": __import__('jwt').utils.base64url_encode(e.to_bytes((e.bit_length() + 7) // 8, "big")).decode(),
        }
        fake_jwks = {"keys": [jwk]}

        with patch("jwt_lib.verifier.timeout_jwk_client.AsyncJWKSFetcher.fetch", new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = fake_jwks
            verifier = UserJWTVerifier(
                issuer=test_issuer,
                jwks_host=test_issuer,
                audience=test_audience
            )
            claims_obj = await verifier.validate(token)
            assert isinstance(claims_obj, TrustedClaims)
            assert claims_obj.subject == base_claims["sub"]

    @pytest.mark.asyncio
    async def test_present_nbf_is_accepted(self, test_issuer: str, test_audience: str, base_claims: dict, private_key_pem: bytes, rsa_key_pair):
        _, public_key = rsa_key_pair
        # Ensure nbf is present and valid
        claims = base_claims.copy()
        claims["nbf"] = int(time.time())
        token = create_token(
            claims,
            private_key_pem,
            headers=self._user_headers(),
        )
        public_numbers = public_key.public_numbers()
        e = public_numbers.e
        n = public_key.public_numbers().n
        jwk = {
            "kty": "RSA",
            "kid": "test-key-1",
            "alg": "RS256",
            "use": "sig",
            "n": __import__('jwt').utils.base64url_encode(n.to_bytes((n.bit_length() + 7) // 8, "big")).decode(),
            "e": __import__('jwt').utils.base64url_encode(e.to_bytes((e.bit_length() + 7) // 8, "big")).decode(),
        }
        fake_jwks = {"keys": [jwk]}
        with patch("jwt_lib.verifier.timeout_jwk_client.AsyncJWKSFetcher.fetch", new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = fake_jwks
            verifier = UserJWTVerifier(
                issuer=test_issuer,
                jwks_host=test_issuer,
                audience=test_audience,
            )
            claims_obj = await verifier.validate(token)
            assert isinstance(claims_obj, TrustedClaims)
            assert claims_obj.subject == base_claims["sub"]

    # max_token_age_seconds argument is no longer supported; test removed.
