"""Authenticator for Auth0-issued service tokens."""

from __future__ import annotations

from typing import Any, Iterable

from jwt_lib.src.claims import TrustedClaims
from jwt_lib.src.profiles import Auth0Profile, TokenProfile
from jwt_lib.src.verifier import Auth0JWTVerifier, JWTVerifier
from jwt_lib.src.validation import ClaimRule

from .authenticator import Authenticator


class Auth0Authenticator(Authenticator):
    """Facade that wires Auth0 verifier + profile using provided kwargs."""

    def __init__(
        self,
        issuer: str,
        jwks_host: str,
        audience: str | None = None,
        allowed_algorithms: Iterable[str] | None = None,
        profile_kwargs: dict[str, Any] | None = None,
    ) -> None:
        super().__init__()
        
        self.issuer = issuer
        self.jwks_host = jwks_host
        self.audience = audience
        self.allowed_algorithms = allowed_algorithms
        self.profile_kwargs = dict(profile_kwargs or {})
        
        self._verifier = self._create_verifier()
        self._profile = self._create_profile()

    def _create_verifier(self) -> JWTVerifier:
        return Auth0JWTVerifier(
            issuer=self.issuer,
            jwks_host=self.jwks_host,
            audience=self.audience,
            allowed_algorithms=self.allowed_algorithms,
        )

    def _create_profile(self) -> TokenProfile:
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
        claims = await self.verifier.validate(token)
        self.profile.validate(claims, extra_rules=extra_rules)
        return claims
