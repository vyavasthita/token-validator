"""Authenticator for Auth0-issued service tokens."""

from __future__ import annotations

import logging
from typing import Any, Iterable

from .authenticator import Authenticator

from jwt_lib.claims import TrustedClaims
from jwt_lib.exceptions import JWTError
from jwt_lib.profiles import Auth0Profile, TokenProfile
from jwt_lib.verifier import Auth0JWTVerifier, JWTVerifier
from jwt_lib.validation import ClaimRule


logger = logging.getLogger(__name__)


class Auth0Authenticator(Authenticator):
    """Facade that wires Auth0 verifier + profile using provided kwargs."""

    def __init__(
        self,
        issuer: str,
        jwks_host: str,
        audience: str | None = None,
        profile_kwargs: dict[str, Any] | None = None,
    ) -> None:
        super().__init__()
        
        # Configuration is stored verbatim and forwarded to verifier/profile.
        self.issuer = issuer
        self.jwks_host = jwks_host
        self.audience = audience
        self.profile_kwargs = dict(profile_kwargs or {})
        
        self._verifier = self._create_verifier()
        self._profile = self._create_profile()

        logger.info(
            f"Initialized Auth0Authenticator issuer={self.issuer}, audience={self.audience}."
        )

    def _create_verifier(self) -> JWTVerifier:
        """Compose an Auth0JWTVerifier using the supplied config."""
        return Auth0JWTVerifier(
            issuer=self.issuer,
            jwks_host=self.jwks_host,
            audience=self.audience,
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
            f"Auth0Authenticator validating token with verifier={self.verifier.__class__.__name__}, profile={self.profile.profile_name}."
        )
        try:
            claims: TrustedClaims = await self.verifier.validate(token)
            logger.info(
                f"Auth0JWTVerifier succeeded issuer={self.issuer}, audience={self.audience}."
            )
            
            await self.profile.validate(claims, extra_rules=extra_rules)
            logger.info(
                f"Auth0Profile validation passed profile={self.profile.profile_name}."
            )
            return claims
        except JWTError as error:
            logger.warning(
                f"Auth0Authenticator validation failed for issuer={self.issuer}: {error}."
            )
            raise
        except Exception:
            logger.exception(
                f"Auth0Authenticator encountered unexpected error. Issuer={self.issuer}."

            )
            raise
