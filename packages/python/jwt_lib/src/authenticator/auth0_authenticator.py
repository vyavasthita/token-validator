"""Authenticator for Auth0-issued service tokens."""

from __future__ import annotations

import logging
from typing import Any, Iterable

from jwt_lib.src.claims import TrustedClaims
from jwt_lib.src.profiles import Auth0Profile, TokenProfile
from jwt_lib.src.verifier import Auth0JWTVerifier, JWTVerifier
from jwt_lib.src.validation import ClaimRule

from .authenticator import Authenticator


logger = logging.getLogger(__name__)


class Auth0Authenticator(Authenticator):
    """Facade that wires Auth0 verifier + profile using provided kwargs.

    Example:
        authenticator = Auth0Authenticator(
            issuer="https://tenant.auth0.com/",
            jwks_host="https://tenant.auth0.com/",
            audience="https://api.example.com",
            profile_kwargs={"expected_tenant": "example"},
        )
        claims = await authenticator.validate(token)
    """

    def __init__(
        self,
        issuer: str,
        jwks_host: str,
        audience: str | None = None,
        allowed_algorithms: Iterable[str] | None = None,
        profile_kwargs: dict[str, Any] | None = None,
    ) -> None:
        super().__init__()
        
        # Configuration is stored verbatim and forwarded to verifier/profile.
        self.issuer = issuer
        self.jwks_host = jwks_host
        self.audience = audience
        self.allowed_algorithms = allowed_algorithms
        self.profile_kwargs = dict(profile_kwargs or {})
        
        self._verifier = self._create_verifier()
        self._profile = self._create_profile()

        logger.debug(
            "Initialized Auth0Authenticator issuer=%s audience=%s allowed_algs=%s",
            self.issuer,
            self.audience,
            self.allowed_algorithms,
        )

    def _create_verifier(self) -> JWTVerifier:
        """Compose an Auth0JWTVerifier using the supplied config."""
        return Auth0JWTVerifier(
            issuer=self.issuer,
            jwks_host=self.jwks_host,
            audience=self.audience,
            allowed_algorithms=self.allowed_algorithms,
        )

    def _create_profile(self) -> TokenProfile:
        """Instantiate the Auth0Profile with any optional overrides."""
        return Auth0Profile(
            issuer=self.issuer,
            audience=self.audience,
            **self.profile_kwargs,
        )

    async def validate(
        self,
        token: str,
        extra_rules: Iterable[ClaimRule] | None = None,
    ) -> TrustedClaims:
        """Verify the token, then run profile + optional claim rules."""
        logger.debug(
            "Auth0Authenticator validating token with verifier=%s profile=%s",
            self.verifier.__class__.__name__,
            self.profile.profile_name,
        )
        try:
            claims: TrustedClaims = await self.verifier.validate(token)
            logger.debug(
                "Auth0JWTVerifier succeeded issuer=%s audience=%s", self.issuer, self.audience
            )
            self.profile.validate(claims, extra_rules=extra_rules)
            logger.debug(
                "Auth0Profile validation passed profile=%s", self.profile.profile_name
            )
            return claims
        except Exception:
            logger.exception("Auth0Authenticator validation failed for issuer=%s", self.issuer)
            raise
