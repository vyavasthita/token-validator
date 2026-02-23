"""Base authenticator that orchestrates verifier and profile validation."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterable

from jwt_lib.src.claims import TrustedClaims
from jwt_lib.src.profiles import TokenProfile
from jwt_lib.src.validation import ClaimRule
from jwt_lib.src.verifier import JWTVerifier


class Authenticator(ABC):
    """Coordinate cryptographic verification followed by profile checks.

    Example:
        class MyAuthenticator(Authenticator):
            def _create_verifier(self) -> JWTVerifier:
                return CustomVerifier(...)

            def _create_profile(self) -> TokenProfile:
                return CustomProfile(...)

            async def validate(self, token: str, extra_rules=None) -> TrustedClaims:
                claims = await self.verifier.validate(token)
                self.profile.validate(claims, extra_rules=extra_rules)
                return claims

    Concrete authenticators must assign `_verifier` and `_profile` during
    initialization (typically by calling `_create_verifier()` and
    `_create_profile()`).
    """

    def __init__(self) -> None:
        """Prepare slots for verifier/profile instances."""
        self._verifier: JWTVerifier = None  # type: ignore[assignment]
        self._profile: TokenProfile = None  # type: ignore[assignment]

    @property
    def verifier(self) -> JWTVerifier:
        """Return the configured JWTVerifier for this authenticator."""
        return self._verifier

    @property
    def profile(self) -> TokenProfile:
        """Return the configured TokenProfile for this authenticator."""
        return self._profile

    @abstractmethod
    def _create_verifier(self) -> JWTVerifier:  # pragma: no cover - abstract
        """Create a JWTVerifier configured for this authenticator."""
        raise NotImplementedError

    @abstractmethod
    def _create_profile(self) -> TokenProfile:  # pragma: no cover - abstract
        """Create a TokenProfile configured for this authenticator."""
        raise NotImplementedError

    @abstractmethod
    async def validate(
        self,
        token: str,
        extra_rules: Iterable[ClaimRule] | None = None,
    ) -> TrustedClaims:  # pragma: no cover - abstract
        """Run cryptographic checks followed by profile business rules."""
        raise NotImplementedError