"""Authenticator for Auth0-issued service tokens."""

from __future__ import annotations

import logging
import time
from typing import Any, Callable, Dict, Iterable, cast

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
        headers_provider: Callable[[], Dict[str, str]] | None = None,
        cache_ttl: float | None = None,
    ) -> None:
        super().__init__()

        # Configuration is stored verbatim and forwarded to verifier/profile.
        self.issuer = issuer
        self.jwks_host = jwks_host
        self.audience = audience
        self.profile_kwargs = dict(profile_kwargs or {})
        self._headers_provider = headers_provider
        self._cache_ttl = cache_ttl

        self._verifier = self._create_verifier()
        self._profile = self._create_profile()

        logger.info(
            f"Auth0Authenticator initialized with issuer={self.issuer}, audience={self.audience}, jwks_url={self.jwks_host}/token/.well-known/jwks.json."
        )

    def _create_verifier(self) -> JWTVerifier:
        """Compose an Auth0JWTVerifier using the supplied config."""
        return Auth0JWTVerifier(
            issuer=self.issuer,
            jwks_host=self.jwks_host,
            audience=self.audience,
            headers_provider=self._headers_provider,
            cache_ttl=self._cache_ttl,
        )

    async def close(self) -> None:
        """Close the underlying JWKS cache httpx client for clean shutdown."""
        await self._verifier.close()
        logger.info("Auth0Authenticator closed.")

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
        auth0_profile = cast(Auth0Profile, self.profile)
        logger.info(
            f"Auth0 token validation started"
            f" issuer={self.issuer},"
            f" audience={self.audience},"
            f" jwks_url={self.jwks_host}/token/.well-known/jwks.json,"
            f" appName={auth0_profile.expected_app_name},"
            f" gty={auth0_profile.expected_grant_type}"
        )
        start = time.monotonic()
        try:
            claims: TrustedClaims = await self.verifier.validate(token)

            await self.profile.validate(claims, extra_rules=extra_rules)

            duration_ms = (time.monotonic() - start) * 1000

            logger.info(
                f"Auth0 token validated successfully"
                f" sub={claims.get('sub', 'N/A')},"
                f" jti={claims.get('jti', 'N/A')},"
                f" scope={claims.get('scope', 'N/A')},"
                f" duration_ms={duration_ms:.1f}"
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
