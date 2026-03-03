"""Auth0-specific JWT verifier."""

from __future__ import annotations

import logging
from typing import Iterable

from .base_verifier import JWTVerifier

from jwt_lib.claims import TrustedClaims
from jwt_lib.config.config import AUTH_0_ALLOWED_ALGORITHMS


logger = logging.getLogger(__name__)


class Auth0JWTVerifier(JWTVerifier):
    """Verifier for Auth0-issued service tokens (minimal extras)."""

    def __init__(
        self,
        issuer: str,
        jwks_host: str,
        audience: str | None = None,
    ) -> None:
        """Initialize the Auth0 verifier with optional allow-list overrides."""

        super().__init__(
            issuer=issuer,
            jwks_host=jwks_host,
            audience=audience,
            allowed_algorithms=AUTH_0_ALLOWED_ALGORITHMS,
        )

    async def validate(self, token: str) -> TrustedClaims:
        """Verify the token and wrap the resulting claims for downstream use."""
        logger.debug(f"Auth0JWTVerifier validating token issuer={self.issuer}.")

        header, claims = await self._verify_token(token)

        return TrustedClaims(claims, headers=header)
