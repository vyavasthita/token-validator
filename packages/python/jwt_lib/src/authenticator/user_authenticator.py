"""Authenticator for user tokens."""

from __future__ import annotations

from typing import Iterable

from jwt_lib.src.claims import TrustedClaims
from jwt_lib.src.profiles import TokenProfile, UserTokenProfile
from jwt_lib.src.config.config import (
    DEFAULT_USER_ALLOWED_ALGORITHMS,
    DEFAULT_USER_AUDIENCE,
    DEFAULT_USER_ISSUER,
)
from jwt_lib.src.verifier import JWTVerifier
from jwt_lib.src.validation import ClaimRule

from .authenticator import Authenticator


class UserAuthenticator(Authenticator):
    """Authenticator for user tokens."""

    def __init__(
        self,
        issuer: str | None = None,
        audience: str | None = None,
    ) -> None:
        super().__init__()
        self.issuer = (issuer or DEFAULT_USER_ISSUER).rstrip("/") + "/"
        self.audience = audience or DEFAULT_USER_AUDIENCE
        self.allowed_algorithms = list(DEFAULT_USER_ALLOWED_ALGORITHMS)
        self._verifier = self._create_verifier()
        self._profile = self._create_profile()

    def _create_verifier(self) -> JWTVerifier:
        return JWTVerifier(
            issuer=self.issuer,
            audience=self.audience,
            allowed_algorithms=self.allowed_algorithms,
        )

    def _create_profile(self) -> TokenProfile:
        return UserTokenProfile(audience=self.audience)

    async def validate(
        self,
        token: str,
        extra_rules: Iterable[ClaimRule] | None = None,
    ) -> TrustedClaims:
        claims = await self.verifier.validate(token)
        self.profile.validate(claims, extra_rules=extra_rules)
        return claims
