"""Tests for the Auth0 JWT verifier."""

import time
from unittest.mock import MagicMock

import pytest
from jwt import PyJWKClient

from jwt_lib.src.claims import TrustedClaims
from jwt_lib.src.exceptions import (
    AlgorithmNotAllowedError,
    ExpiredTokenError,
    InvalidAudienceError,
    InvalidIssuerError,
    InvalidTokenError,
    SigningKeyNotFoundError,
    TokenNotYetValidError,
)
from jwt_lib.src.verifier import Auth0JWTVerifier
from jwt_lib.tests.conftest import create_token


class TestAuth0JWTVerifierInitialization:
    """Tests for Auth0JWTVerifier initialization."""

    def test_default_algorithm(self):
        verifier = Auth0JWTVerifier(
            issuer="https://auth.example.com/",
            jwks_host="https://auth.example.com/",
        )
        assert "RS256" in verifier.allowed_algorithms

    def test_custom_algorithms(self):
        verifier = Auth0JWTVerifier(
            issuer="https://auth.example.com/",
            jwks_host="https://auth.example.com/",
            allowed_algorithms=["RS256", "RS384"],
        )
        assert verifier.allowed_algorithms == {"RS256", "RS384"}

    def test_preserves_issuer_string(self):
        verifier = Auth0JWTVerifier(
            issuer="https://auth.example.com",
            jwks_host="https://auth.example.com",
        )
        assert verifier.issuer == "https://auth.example.com"

    def test_default_required_claims(self):
        verifier = Auth0JWTVerifier(
            issuer="https://auth.example.com/",
            jwks_host="https://auth.example.com/",
        )
        assert {"exp", "iss", "sub"}.issubset(verifier.required_claims)

    def test_audience_adds_aud_to_required(self):
        verifier = Auth0JWTVerifier(
            issuer="https://auth.example.com/",
            jwks_host="https://auth.example.com/",
            audience="my-api",
        )
        assert "aud" in verifier.required_claims

    def test_custom_required_claims(self):
        verifier = Auth0JWTVerifier(
            issuer="https://auth.example.com/",
            jwks_host="https://auth.example.com/",
            required_claims=["exp", "custom"],
        )
        assert "custom" in verifier.required_claims

    def test_builds_default_jwks_uri(self):
        verifier = Auth0JWTVerifier(
            issuer="https://auth.example.com/",
            jwks_host="https://auth.example.com/",
        )
        assert verifier.jwks_uri == "https://auth.example.com/token/.well-known/jwks.json"

    def test_accepts_custom_jwks_host(self):
        verifier = Auth0JWTVerifier(
            issuer="https://auth.example.com/",
            jwks_host="https://keys.example.net",
        )
        assert verifier.jwks_uri == "https://keys.example.net/token/.well-known/jwks.json"

    def test_trims_trailing_slashes_on_jwks_host(self):
        verifier = Auth0JWTVerifier(
            issuer="https://auth.example.com/",
            jwks_host="https://auth.example.com///",
        )
        assert verifier.jwks_host == "https://auth.example.com"

    def test_allows_empty_issuer(self):
        verifier = Auth0JWTVerifier(issuer="", jwks_host="https://auth.example.com")
        assert verifier.issuer == ""

    def test_allows_empty_jwks_host(self):
        verifier = Auth0JWTVerifier(issuer="https://auth.example.com/", jwks_host="")
        assert verifier.jwks_uri == "/token/.well-known/jwks.json"


class TestAuth0JWTVerifierValidation:
    """Tests for JWT verification."""

    @pytest.mark.asyncio
    async def test_verify_valid_token(
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
            headers={"kid": "test-key-1"},
        )

        mock_signing_key = MagicMock()
        mock_signing_key.key = public_key
        mock_jwks_client = MagicMock(spec=PyJWKClient)
        mock_jwks_client.get_signing_key_from_jwt.return_value = mock_signing_key

        verifier = Auth0JWTVerifier(
            issuer=test_issuer,
            jwks_host=test_issuer,
            audience=test_audience,
        )
        verifier._jwks_client = mock_jwks_client

        claims = await verifier.validate(token)

        assert isinstance(claims, TrustedClaims)
        assert claims.subject == "user123"
        assert claims.issuer == test_issuer

    @pytest.mark.asyncio
    async def test_rejects_issuer_without_trailing_slash(
        self,
        test_issuer: str,
        test_audience: str,
        base_claims: dict,
        private_key_pem: bytes,
        rsa_key_pair,
    ):
        _, public_key = rsa_key_pair

        claims_without_slash = base_claims.copy()
        claims_without_slash["iss"] = claims_without_slash["iss"].rstrip("/")

        token = create_token(
            claims_without_slash,
            private_key_pem,
            headers={"kid": "test-key-1"},
        )

        mock_signing_key = MagicMock()
        mock_signing_key.key = public_key
        mock_jwks_client = MagicMock(spec=PyJWKClient)
        mock_jwks_client.get_signing_key_from_jwt.return_value = mock_signing_key

        verifier = Auth0JWTVerifier(
            issuer=test_issuer,
            jwks_host=test_issuer,
            audience=test_audience,
        )
        verifier._jwks_client = mock_jwks_client

        with pytest.raises(InvalidIssuerError):
            await verifier.validate(token)


class TestAuth0JWTVerifierErrors:
    """Tests for JWT verification error cases."""

    @pytest.mark.asyncio
    async def test_expired_token(
        self,
        test_issuer: str,
        test_audience: str,
        private_key_pem: bytes,
        rsa_key_pair,
    ):
        _, public_key = rsa_key_pair

        expired_claims = {
            "iss": test_issuer,
            "aud": test_audience,
            "sub": "user123",
            "exp": int(time.time()) - 3600,
            "iat": int(time.time()) - 7200,
        }

        token = create_token(
            expired_claims,
            private_key_pem,
            headers={"kid": "test-key-1"},
        )

        mock_signing_key = MagicMock()
        mock_signing_key.key = public_key
        mock_jwks_client = MagicMock(spec=PyJWKClient)
        mock_jwks_client.get_signing_key_from_jwt.return_value = mock_signing_key

        verifier = Auth0JWTVerifier(
            issuer=test_issuer,
            jwks_host=test_issuer,
            audience=test_audience,
        )
        verifier._jwks_client = mock_jwks_client

        with pytest.raises(ExpiredTokenError):
            await verifier.validate(token)

    @pytest.mark.asyncio
    async def test_token_not_yet_valid(
        self,
        test_issuer: str,
        test_audience: str,
        private_key_pem: bytes,
        rsa_key_pair,
    ):
        _, public_key = rsa_key_pair

        future_nbf_claims = {
            "iss": test_issuer,
            "aud": test_audience,
            "sub": "user123",
            "exp": int(time.time()) + 7200,
            "nbf": int(time.time()) + 3600,
        }

        token = create_token(
            future_nbf_claims,
            private_key_pem,
            headers={"kid": "test-key-1"},
        )

        mock_signing_key = MagicMock()
        mock_signing_key.key = public_key
        mock_jwks_client = MagicMock(spec=PyJWKClient)
        mock_jwks_client.get_signing_key_from_jwt.return_value = mock_signing_key

        verifier = Auth0JWTVerifier(
            issuer=test_issuer,
            jwks_host=test_issuer,
            audience=test_audience,
        )
        verifier._jwks_client = mock_jwks_client

        with pytest.raises(TokenNotYetValidError):
            await verifier.validate(token)

    @pytest.mark.asyncio
    async def test_wrong_issuer(
        self,
        test_audience: str,
        base_claims: dict,
        private_key_pem: bytes,
        rsa_key_pair,
    ):
        _, public_key = rsa_key_pair

        token = create_token(
            base_claims,
            private_key_pem,
            headers={"kid": "test-key-1"},
        )

        mock_signing_key = MagicMock()
        mock_signing_key.key = public_key
        mock_jwks_client = MagicMock(spec=PyJWKClient)
        mock_jwks_client.get_signing_key_from_jwt.return_value = mock_signing_key

        wrong_issuer = "https://wrong-issuer.com/"

        verifier = Auth0JWTVerifier(
            issuer=wrong_issuer,
            jwks_host=wrong_issuer,
            audience=test_audience,
        )
        verifier._jwks_client = mock_jwks_client

        with pytest.raises(InvalidIssuerError):
            await verifier.validate(token)

    @pytest.mark.asyncio
    async def test_wrong_audience(
        self,
        test_issuer: str,
        base_claims: dict,
        private_key_pem: bytes,
        rsa_key_pair,
    ):
        _, public_key = rsa_key_pair

        token = create_token(
            base_claims,
            private_key_pem,
            headers={"kid": "test-key-1"},
        )

        mock_signing_key = MagicMock()
        mock_signing_key.key = public_key
        mock_jwks_client = MagicMock(spec=PyJWKClient)
        mock_jwks_client.get_signing_key_from_jwt.return_value = mock_signing_key

        verifier = Auth0JWTVerifier(
            issuer=test_issuer,
            jwks_host=test_issuer,
            audience="wrong-audience",
        )
        verifier._jwks_client = mock_jwks_client

        with pytest.raises(InvalidAudienceError):
            await verifier.validate(token)

    @pytest.mark.asyncio
    async def test_algorithm_not_allowed(
        self,
        test_issuer: str,
        test_audience: str,
        base_claims: dict,
        private_key_pem: bytes,
    ):
        token = create_token(
            base_claims,
            private_key_pem,
            algorithm="RS256",
            headers={"kid": "test-key-1"},
        )

        verifier = Auth0JWTVerifier(
            issuer=test_issuer,
            jwks_host=test_issuer,
            audience=test_audience,
            allowed_algorithms=["RS384"],
        )

        with pytest.raises(AlgorithmNotAllowedError) as exc_info:
            await verifier.validate(token)

        assert "RS256" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_invalid_token_format(
        self,
        test_issuer: str,
        test_audience: str,
    ):
        verifier = Auth0JWTVerifier(
            issuer=test_issuer,
            jwks_host=test_issuer,
            audience=test_audience,
        )

        with pytest.raises(InvalidTokenError):
            await verifier.validate("not.a.valid.token")

    @pytest.mark.asyncio
    async def test_signing_key_not_found(
        self,
        test_issuer: str,
        test_audience: str,
        base_claims: dict,
        private_key_pem: bytes,
    ):
        token = create_token(
            base_claims,
            private_key_pem,
            headers={"kid": "unknown-key-id"},
        )

        mock_jwks_client = MagicMock(spec=PyJWKClient)
        mock_jwks_client.get_signing_key_from_jwt.side_effect = Exception("Key not found")

        verifier = Auth0JWTVerifier(
            issuer=test_issuer,
            jwks_host=test_issuer,
            audience=test_audience,
        )
        verifier._jwks_client = mock_jwks_client

        with pytest.raises(SigningKeyNotFoundError):
            await verifier.validate(token)


class TestAuth0JWTVerifierWithoutAudience:
    """Tests for JWT verification without audience requirement."""

    @pytest.mark.asyncio
    async def test_verify_without_audience(
        self,
        test_issuer: str,
        private_key_pem: bytes,
        rsa_key_pair,
    ):
        _, public_key = rsa_key_pair

        claims = {
            "iss": test_issuer,
            "sub": "user123",
            "exp": int(time.time()) + 3600,
        }

        token = create_token(
            claims,
            private_key_pem,
            headers={"kid": "test-key-1"},
        )

        mock_signing_key = MagicMock()
        mock_signing_key.key = public_key
        mock_jwks_client = MagicMock(spec=PyJWKClient)
        mock_jwks_client.get_signing_key_from_jwt.return_value = mock_signing_key

        verifier = Auth0JWTVerifier(
            issuer=test_issuer,
            jwks_host=test_issuer,
            audience=None,
        )
        verifier._jwks_client = mock_jwks_client

        claims_obj = await verifier.validate(token)
        assert isinstance(claims_obj, TrustedClaims)
        assert claims_obj.subject == "user123"
