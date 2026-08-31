"""Auth0-specific JWT verifier."""

from __future__ import annotations

import logging
from typing import Callable, Dict

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
        headers_provider: Callable[[], Dict[str, str]] | None = None,
        cache_ttl: float | None = None,
    ) -> None:
        """Initialize the Auth0 verifier with optional allow-list overrides.

        Parameters
        ----------
        cache_ttl:
            JWKS cache TTL in seconds. Passed through to JWKSCache.
            When None, the library default from config is used.
        """
        super().__init__(
            issuer=issuer,
            jwks_host=jwks_host,
            audience=audience,
            allowed_algorithms=AUTH_0_ALLOWED_ALGORITHMS,
            headers_provider=headers_provider,
            cache_ttl=cache_ttl,
        )

    async def validate(self, token: str) -> TrustedClaims:
        """Verify the token and wrap the resulting claims for downstream use."""
        header, claims = await self._verify_token(token)

        logger.debug("Auth0JWTVerifier succeeded.")
        return TrustedClaims(claims, headers=header)
