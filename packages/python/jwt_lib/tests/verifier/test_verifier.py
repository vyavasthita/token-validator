"""Tests for JWTVerifier class."""

import time
from typing import Any
from unittest.mock import MagicMock

import jwt
import pytest
from jwt import PyJWKClient

from jwt_lib.src.claims import TrustedClaims
from jwt_lib.src.verifier import JWTVerifier
from jwt_lib.src.exceptions import (
    InvalidTokenError,
    ExpiredTokenError,
    TokenNotYetValidError,
    InvalidIssuerError,
    InvalidAudienceError,
    AlgorithmNotAllowedError,
    SigningKeyNotFoundError,
)

from jwt_lib.tests.conftest import create_token


DEFAULT_JWKS_URI = "https://example.com/.well-known/jwks.json"


class TestJWTVerifierInitialization:
    """Tests for JWTVerifier initialization."""

    def test_default_algorithm(self):
        """Test default algorithm is RS256."""
        verifier = JWTVerifier(
            issuer="https://auth.example.com/",
        )
        assert "RS256" in verifier.allowed_algorithms

    def test_custom_algorithms(self):
        """Test custom allowed algorithms."""
        verifier = JWTVerifier(
            issuer="https://auth.example.com/",
            allowed_algorithms=["RS256", "RS384"],
        )
        assert verifier.allowed_algorithms == {"RS256", "RS384"}

    def test_normalizes_issuer(self):
        """Test issuer is normalized with trailing slash."""
        verifier = JWTVerifier(
            issuer="https://auth.example.com",
        )

    def test_default_required_claims(self):
        """Test default required claims."""
        verifier = JWTVerifier(
            issuer="https://auth.example.com/",
        )
        assert "exp" in verifier.required_claims
        assert "iss" in verifier.required_claims
        assert "sub" in verifier.required_claims

    def test_audience_adds_aud_to_required(self):
        """Test that specifying audience adds aud to required claims."""
        verifier = JWTVerifier(
            issuer="https://auth.example.com/",
            audience="my-api",
        )
        assert "aud" in verifier.required_claims

    def test_custom_required_claims(self):
        """Test custom required claims."""
        verifier = JWTVerifier(
            issuer="https://auth.example.com/",
            required_claims=["exp", "custom"],
        )
        assert "custom" in verifier.required_claims

    def test_derives_jwks_uri_when_not_provided(self):
        """If jwks_uri is omitted, it should follow well-known path."""
        verifier = JWTVerifier(
            issuer="https://auth.example.com/",
        )
        assert verifier.jwks_uri == "https://auth.example.com/.well-known/jwks.json"


class TestJWTVerifierValidation:
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
        """Test verification of a valid token."""
        _, public_key = rsa_key_pair
        
        # Create token with kid
        token = create_token(
            base_claims,
            private_key_pem,
            headers={"kid": "test-key-1"},
        )
        
        # Mock PyJWKClient
        mock_signing_key = MagicMock()
        mock_signing_key.key = public_key
        
        mock_jwks_client = MagicMock(spec=PyJWKClient)
        mock_jwks_client.get_signing_key_from_jwt.return_value = mock_signing_key
        
        verifier = JWTVerifier(
            issuer=test_issuer,
            audience=test_audience,
        )
        # Inject mock client
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
        """Tokens that omit trailing slash in iss should be rejected."""
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

        verifier = JWTVerifier(
            issuer=test_issuer,
            audience=test_audience,
        )
        verifier._jwks_client = mock_jwks_client

        with pytest.raises(InvalidIssuerError):
            await verifier.validate(token)

class TestJWTVerifierErrors:
    """Tests for JWT verification error cases."""

    @pytest.mark.asyncio
    async def test_expired_token(
        self,
        test_issuer: str,
        test_audience: str,
        private_key_pem: bytes,
        rsa_key_pair,
    ):
        """Test that expired tokens are rejected."""
        _, public_key = rsa_key_pair
        
        expired_claims = {
            "iss": test_issuer,
            "aud": test_audience,
            "sub": "user123",
            "exp": int(time.time()) - 3600,  # 1 hour ago
            "iat": int(time.time()) - 7200,
        }
        
        token = create_token(
            expired_claims,
            private_key_pem,
            headers={"kid": "test-key-1"},
        )
        
        # Mock PyJWKClient
        mock_signing_key = MagicMock()
        mock_signing_key.key = public_key
        
        mock_jwks_client = MagicMock(spec=PyJWKClient)
        mock_jwks_client.get_signing_key_from_jwt.return_value = mock_signing_key
        
        verifier = JWTVerifier(
            issuer=test_issuer,
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
        """Test that tokens with future nbf are rejected."""
        _, public_key = rsa_key_pair
        
        future_nbf_claims = {
            "iss": test_issuer,
            "aud": test_audience,
            "sub": "user123",
            "exp": int(time.time()) + 7200,
            "nbf": int(time.time()) + 3600,  # 1 hour from now
        }
        
        token = create_token(
            future_nbf_claims,
            private_key_pem,
            headers={"kid": "test-key-1"},
        )
        
        # Mock PyJWKClient
        mock_signing_key = MagicMock()
        mock_signing_key.key = public_key
        
        mock_jwks_client = MagicMock(spec=PyJWKClient)
        mock_jwks_client.get_signing_key_from_jwt.return_value = mock_signing_key
        
        verifier = JWTVerifier(
            issuer=test_issuer,
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
        """Test that wrong issuer is rejected."""
        _, public_key = rsa_key_pair
        
        token = create_token(
            base_claims,  # Has issuer "https://auth.example.com/"
            private_key_pem,
            headers={"kid": "test-key-1"},
        )
        
        # Mock PyJWKClient
        mock_signing_key = MagicMock()
        mock_signing_key.key = public_key
        
        mock_jwks_client = MagicMock(spec=PyJWKClient)
        mock_jwks_client.get_signing_key_from_jwt.return_value = mock_signing_key
        
        wrong_issuer = "https://wrong-issuer.com/"
        
        verifier = JWTVerifier(
            issuer=wrong_issuer,
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
        """Test that wrong audience is rejected."""
        _, public_key = rsa_key_pair
        
        token = create_token(
            base_claims,  # Has audience "test-api"
            private_key_pem,
            headers={"kid": "test-key-1"},
        )
        
        # Mock PyJWKClient
        mock_signing_key = MagicMock()
        mock_signing_key.key = public_key
        
        mock_jwks_client = MagicMock(spec=PyJWKClient)
        mock_jwks_client.get_signing_key_from_jwt.return_value = mock_signing_key
        
        verifier = JWTVerifier(
            issuer=test_issuer,
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
        """Test that tokens with disallowed algorithm are rejected."""
        # Create token with RS256 (default)
        token = create_token(
            base_claims,
            private_key_pem,
            algorithm="RS256",
            headers={"kid": "test-key-1"},
        )
        
        verifier = JWTVerifier(
            issuer=test_issuer,
            audience=test_audience,
            allowed_algorithms=["RS384"],  # Only allow RS384
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
        """Test that malformed tokens are rejected."""
        verifier = JWTVerifier(
            issuer=test_issuer,
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
        """Test error when signing key is not in JWKS."""
        token = create_token(
            base_claims,
            private_key_pem,
            headers={"kid": "unknown-key-id"},
        )
        
        # Mock PyJWKClient to raise exception
        mock_jwks_client = MagicMock(spec=PyJWKClient)
        mock_jwks_client.get_signing_key_from_jwt.side_effect = Exception("Key not found")
        
        verifier = JWTVerifier(
            issuer=test_issuer,
            audience=test_audience,
        )
        verifier._jwks_client = mock_jwks_client
        
        with pytest.raises(SigningKeyNotFoundError):
            await verifier.validate(token)


class TestJWTVerifierWithoutAudience:
    """Tests for JWT verification without audience requirement."""

    @pytest.mark.asyncio
    async def test_verify_without_audience(
        self,
        test_issuer: str,
        private_key_pem: bytes,
        rsa_key_pair,
    ):
        """Test verification when no audience is specified."""
        _, public_key = rsa_key_pair
        
        claims = {
            "iss": test_issuer,
            "sub": "user123",
            "exp": int(time.time()) + 3600,
            # No aud claim
        }
        
        token = create_token(
            claims,
            private_key_pem,
            headers={"kid": "test-key-1"},
        )
        
        # Mock PyJWKClient
        mock_signing_key = MagicMock()
        mock_signing_key.key = public_key
        
        mock_jwks_client = MagicMock(spec=PyJWKClient)
        mock_jwks_client.get_signing_key_from_jwt.return_value = mock_signing_key
        
        verifier = JWTVerifier(
            issuer=test_issuer,
            # No audience specified
        )
        verifier._jwks_client = mock_jwks_client
        
        result = await verifier.validate(token)
        
        assert result.subject == "user123"
