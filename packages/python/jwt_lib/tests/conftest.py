"""
Pytest fixtures and utilities for JWT library tests.

Provides fixtures for:
- RSA key pair generation
- JWT token creation
"""

import time
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


@pytest.fixture
def rsa_key_pair() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Generate an RSA key pair for signing and verification."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key


@pytest.fixture
def private_key_pem(rsa_key_pair: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]) -> bytes:
    """Get the private key in PEM format."""
    private_key, _ = rsa_key_pair
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


@pytest.fixture
def test_issuer() -> str:
    """Test issuer URL."""
    return "https://auth.example.com/"


@pytest.fixture
def test_audience() -> str:
    """Test audience."""
    return "test-api"


@pytest.fixture
def base_claims(test_issuer: str, test_audience: str) -> dict[str, Any]:
    """Base claims for a valid JWT."""
    now = int(time.time())
    return {
        "iss": test_issuer,
        "aud": test_audience,
        "sub": "user123",
        "exp": now + 3600,  # 1 hour from now
        "iat": now,
        "nbf": now,
    }


@pytest.fixture
def expired_claims(base_claims: dict[str, Any]) -> dict[str, Any]:
    """Claims for an expired JWT."""
    claims = base_claims.copy()
    claims["exp"] = int(time.time()) - 3600  # 1 hour ago
    return claims


@pytest.fixture
def future_nbf_claims(base_claims: dict[str, Any]) -> dict[str, Any]:
    """Claims for a JWT that is not yet valid."""
    claims = base_claims.copy()
    claims["nbf"] = int(time.time()) + 3600  # 1 hour from now
    return claims


def create_token(
    claims: dict[str, Any],
    private_key_pem: bytes,
    algorithm: str = "RS256",
    headers: dict[str, Any] | None = None,
) -> str:
    """
    Create a signed JWT token.
    
    Args:
        claims: The token claims.
        private_key_pem: The private key in PEM format.
        algorithm: The signing algorithm.
        headers: Additional headers.
    
    Returns:
        The signed JWT token string.
    """
    return jwt.encode(
        claims,
        private_key_pem,
        algorithm=algorithm,
        headers=headers,
    )


@pytest.fixture
def valid_token(base_claims: dict[str, Any], private_key_pem: bytes) -> str:
    """Create a valid signed JWT token."""
    return create_token(base_claims, private_key_pem)


@pytest.fixture
def expired_token(expired_claims: dict[str, Any], private_key_pem: bytes) -> str:
    """Create an expired JWT token."""
    return create_token(expired_claims, private_key_pem)


@pytest.fixture
def future_nbf_token(future_nbf_claims: dict[str, Any], private_key_pem: bytes) -> str:
    """Create a token that is not yet valid."""
    return create_token(future_nbf_claims, private_key_pem)


@pytest.fixture
def token_with_kid(base_claims: dict[str, Any], private_key_pem: bytes) -> str:
    """Create a valid token with a key ID in the header."""
    return create_token(
        base_claims,
        private_key_pem,
        headers={"kid": "test-key-1"},
    )
