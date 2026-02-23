"""Auth0-specific JWT verifier."""

from __future__ import annotations

from typing import Iterable

from jwt_lib.src.claims import TrustedClaims
from jwt_lib.src.config.config import DEFAULT_AUTH0_ALLOWED_ALGORITHMS

from .base_verifier import JWTVerifier


class Auth0JWTVerifier(JWTVerifier):
    """Verifier for Auth0-issued service tokens (minimal extras).

    Example:
        verifier = Auth0JWTVerifier(
            issuer="https://tenant.auth0.com/",
            jwks_host="https://tenant.auth0.com/",
            audience="https://api.example.com",
        )
        claims = await verifier.validate(encoded_jwt)
    """

    DEFAULT_ALLOWED_ALGORITHMS = DEFAULT_AUTH0_ALLOWED_ALGORITHMS

    def __init__(
        self,
        issuer: str,
        jwks_host: str,
        audience: str | None = None,
        allowed_algorithms: Iterable[str] | None = None,
        required_claims: list[str] | None = None,
    ) -> None:
        """Initialize the Auth0 verifier with optional allow-list overrides."""
        super().__init__(
            issuer=issuer,
            jwks_host=jwks_host,
            audience=audience,
            allowed_algorithms=allowed_algorithms,
            required_claims=required_claims,
        )

    async def validate(self, token: str) -> TrustedClaims:
        """Verify the token and wrap the resulting claims for downstream use."""
        header, claims = await self._verify_token(token)
        return TrustedClaims(claims, headers=header)
