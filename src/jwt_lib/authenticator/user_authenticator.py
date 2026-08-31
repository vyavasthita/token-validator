"""Authenticator for user tokens."""

from __future__ import annotations

import logging
import time
from typing import Callable, Dict, Iterable, cast

from .authenticator import Authenticator

from jwt_lib.claims import TrustedClaims
from jwt_lib.exceptions import ConfigurationError, JWTError
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
        headers_provider: Callable[[], Dict[str, str]] | None = None,
        cache_ttl: float | None = None,
    ) -> None:
        super().__init__()

        if not issuer:
            msg = "UserAuthenticator requires a non-empty 'issuer'."
            logger.error(msg)
            raise ConfigurationError(msg)
        if not jwks_host:
            msg = "UserAuthenticator requires a non-empty 'jwks_host'."
            logger.error(msg)
            raise ConfigurationError(msg)
        if not audience:
            msg = "UserAuthenticator requires a non-empty 'audience'."
            logger.error(msg)
            raise ConfigurationError(msg)

        self.issuer = issuer
        self.jwks_host = jwks_host
        self.audience = audience
        self._headers_provider = headers_provider
        self._cache_ttl = cache_ttl

        self._verifier = self._create_verifier()
        self._profile = self._create_profile()

        logger.info(
            f"UserAuthenticator initialized with issuer={self.issuer}, audience={self.audience}, jwks_url={self.jwks_host}/token/.well-known/jwks.json."
        )

    def _create_verifier(self) -> JWTVerifier:
        """Build the UserJWTVerifier with any caller-supplied allow-list."""
        return UserJWTVerifier(
            issuer=self.issuer,
            jwks_host=self.jwks_host,
            audience=self.audience,
            headers_provider=self._headers_provider,
            cache_ttl=self._cache_ttl,
        )

    async def close(self) -> None:
        """Close the underlying JWKS cache httpx client for clean shutdown."""
        await self._verifier.close()
        logger.info("UserAuthenticator closed.")

    def _create_profile(self) -> TokenProfile:
        """Instantiate the strict profile used for claims validation."""
        return UserProfile(issuer=self.issuer, audience=self.audience)

    async def validate(
        self,
        token: str,
        extra_rules: Iterable[ClaimRule] | None = None,
    ) -> TrustedClaims:
        """Verify the token and enforce profile + optional claim rules."""
        user_profile = cast(UserProfile, self.profile)
        logger.info(
            f"User token validation started"
            f" issuer={self.issuer},"
            f" audience={self.audience},"
            f" jwks_url={self.jwks_host}/token/.well-known/jwks.json,"
            f" tokenType={user_profile.expected_token_type},"
            f" principalType={user_profile.expected_principal_type},"
            f" connectionMethods={','.join(user_profile.expected_connection_methods)}"
        )
        start = time.monotonic()
        try:
            claims: TrustedClaims = await self.verifier.validate(token)
            await self.profile.validate(claims, extra_rules=extra_rules)
            duration_ms = (time.monotonic() - start) * 1000
            logger.info(
                f"User token validated successfully"
                f" uid={claims.get('uid', 'N/A')},"
                f" tid={claims.get('tid', 'N/A')},"
                f" jti={claims.get('jti', 'N/A')},"
                f" duration_ms={duration_ms:.1f}"
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
