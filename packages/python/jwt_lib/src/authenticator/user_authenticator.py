"""Authenticator for user tokens."""

from __future__ import annotations

import logging
from typing import Iterable

from jwt_lib.src.claims import TrustedClaims
from jwt_lib.src.exceptions import JWTError
from jwt_lib.src.profiles import TokenProfile, UserProfile
from jwt_lib.src.verifier import JWTVerifier, UserJWTVerifier
from jwt_lib.src.validation import ClaimRule

from .authenticator import Authenticator


logger = logging.getLogger(__name__)


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

        logger.debug(
            "Initialized UserAuthenticator issuer=%s audience=%s allowed_algs=%s",
            self.issuer,
            self.audience,
            self.allowed_algorithms,
        )

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
        logger.debug(
            "UserAuthenticator validating token with verifier=%s profile=%s",
            self.verifier.__class__.__name__,
            self.profile.profile_name,
        )
        try:
            claims: TrustedClaims = await self.verifier.validate(token)
            logger.debug(
                "UserJWTVerifier succeeded issuer=%s audience=%s", self.issuer, self.audience
            )
            self.profile.validate(claims, extra_rules=extra_rules)
            logger.debug(
                "UserProfile validation passed profile=%s", self.profile.profile_name
            )
            return claims
        except JWTError as error:
            logger.warning(
                "UserAuthenticator validation failed for issuer=%s: %s",
                self.issuer,
                error,
            )
            raise
        except Exception:
            logger.exception(
                "UserAuthenticator encountered unexpected error issuer=%s",
                self.issuer,
            )
            raise
