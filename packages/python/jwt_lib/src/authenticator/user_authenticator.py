"""Authenticator for user tokens."""

from __future__ import annotations

from typing import Iterable

from jwt_lib.src.claims import TrustedClaims
from jwt_lib.src.profiles import TokenProfile, UserProfile
from jwt_lib.src.verifier import JWTVerifier, UserJWTVerifier
from jwt_lib.src.validation import ClaimRule

from .authenticator import Authenticator


class UserAuthenticator(Authenticator):
    """Authenticator for first-party user tokens.

    Example:
        authenticator = UserAuthenticator(
            issuer="https://login.example.com/",
            jwks_host="https://login.example.com/",
            audience="my-api",
        )
        claims = await authenticator.validate(token)
    """

    def __init__(
        self,
        issuer: str,
        jwks_host: str,
        audience: str | None = None,
        allowed_algorithms: Iterable[str] | None = None,
    ) -> None:
        super().__init__()
        # Store thin configuration that gets forwarded to the verifier/profile.
        self.issuer = issuer
        self.jwks_host = jwks_host
        self.audience = audience
        self.allowed_algorithms = allowed_algorithms
        
        self._verifier = self._create_verifier()
        self._profile = self._create_profile()

    def _create_verifier(self) -> JWTVerifier:
        """Build the UserJWTVerifier with any caller-supplied allow-list."""
        return UserJWTVerifier(
            issuer=self.issuer,
            jwks_host=self.jwks_host,
            audience=self.audience,
            allowed_algorithms=self.allowed_algorithms,
        )

    def _create_profile(self) -> TokenProfile:
        """Instantiate the strict profile used for claims validation."""
        return UserProfile(issuer=self.issuer, audience=self.audience)

    async def validate(
        self,
        token: str,
        extra_rules: Iterable[ClaimRule] | None = None,
    ) -> TrustedClaims:
        """Verify the token and enforce profile + optional claim rules."""
        claims: TrustedClaims = await self.verifier.validate(token)
        self.profile.validate(claims, extra_rules=extra_rules)
        return claims
