"""Authenticator for user tokens."""

from __future__ import annotations

import logging
from typing import Iterable

from .authenticator import Authenticator

from jwt_lib.claims import TrustedClaims
from jwt_lib.exceptions import JWTError
from jwt_lib.profiles import TokenProfile, UserProfile
from jwt_lib.verifier import JWTVerifier, UserJWTVerifier
from jwt_lib.validation import ClaimRule


logger = logging.getLogger(__name__)


class UserAuthenticator(Authenticator):
    """Authenticator for first-party user tokens."""

    def __init__(
        self,
        issuer: str,
        jwks_host: str,
        audience: str,
    ) -> None:
        super().__init__()
        # Store thin configuration that gets forwarded to the verifier/profile.

        self.issuer = issuer
        self.jwks_host = jwks_host
        self.audience = audience
        
        self._verifier = self._create_verifier()
        self._profile = self._create_profile()

        logger.info(
            f"Initialized UserAuthenticator issuer={self.issuer}, audience={self.audience}."
        )

    def _create_verifier(self) -> JWTVerifier:
        """Build the UserJWTVerifier with any caller-supplied allow-list."""
        return UserJWTVerifier(
            issuer=self.issuer,
            jwks_host=self.jwks_host,
            audience=self.audience,
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

        try:
            claims: TrustedClaims = await self.verifier.validate(token)
            logger.info(
                f"UserJWTVerifier succeeded issuer={self.issuer}, audience={self.audience}."
            )

            await self.profile.validate(claims, extra_rules=extra_rules)
            logger.info(
                f"UserProfile validation passed profile={self.profile.profile_name}."
            )

            return claims
        except JWTError as error:
            logger.warning(
                f"UserAuthenticator validation failed for issuer={self.issuer}, error={error}"
            )
            raise
        except Exception:
            logger.exception(
                f"UserAuthenticator encountered unexpected error issuer={self.issuer}"
            )
            raise
