"""Auth0-specific JWT verifier."""

from __future__ import annotations

from typing import Iterable

from jwt_lib.src.claims import TrustedClaims
from jwt_lib.src.config.config import DEFAULT_AUTH0_ALLOWED_ALGORITHMS

from .base_verifier import JWTVerifier


class Auth0JWTVerifier(JWTVerifier):
    """Verifier for Auth0-issued service tokens (minimal extras)."""

    def __init__(
        self,
        issuer: str,
        audience: str | None = None,
        allowed_algorithms: Iterable[str] | None = None,
        required_claims: list[str] | None = None,
    ) -> None:
        super().__init__(
            issuer=issuer,
            audience=audience,
            allowed_algorithms=allowed_algorithms or DEFAULT_AUTH0_ALLOWED_ALGORITHMS,
            required_claims=required_claims,
        )

    async def validate(self, token: str) -> TrustedClaims:
        header, claims = await self._verify_token(token)
        return TrustedClaims(claims, headers=header)
