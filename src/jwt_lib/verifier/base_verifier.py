"""Base infrastructure for verifying JWTs against JWKS."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, Iterable
import jwt
from jwt.types import Options
from jwt.exceptions import (
    ExpiredSignatureError,
    ImmatureSignatureError,
    InvalidAudienceError as PyJWTInvalidAudienceError,
    InvalidIssuerError as PyJWTInvalidIssuerError,
    InvalidTokenError as PyJWTInvalidTokenError,
)

from jwt_lib.verifier.jwks_cache import JWKSCache
from jwt_lib.config.config import (
    JWKS_FETCH_TIMEOUT_SECONDS,
    JWKS_CACHE_TTL_SECONDS,
    REQUIRED_CLAIMS,
)
from jwt_lib.claims import TrustedClaims


from jwt_lib.exceptions import (
    AlgorithmNotAllowedError,
    ExpiredTokenError,
    InvalidAudienceError,
    InvalidIssuerError,
    InvalidTokenError,
    SigningKeyNotFoundError,
    TokenNotYetValidError,
)

logger = logging.getLogger(__name__)


class JWTVerifier(ABC):
    """Abstract verifier that handles the shared JWKS + PyJWT workflow.

    Uses a unified JWKSCache that maintains a single dict of kid → parsed
    public key objects with configurable TTL and refresh-on-miss for key rotation.
    """

    def __init__(
        self,
        issuer: str,
        jwks_host: str,
        allowed_algorithms: Iterable[str],
        audience: str | None = None,
        headers_provider: Callable[[], Dict[str, str]] | None = None,
        cache_ttl: float | None = None,
    ) -> None:
        """Store verifier configuration and build the unified JWKS cache.

        Parameters
        ----------
        cache_ttl:
            JWKS cache TTL in seconds. When None, falls back to the library
            default (JWKS_CACHE_TTL_SECONDS from config). The consuming
            service can override this to control refresh frequency.
        """
        self.issuer = issuer
        self.jwks_host = jwks_host
        self.audience = audience
        self.allowed_algorithms = set(allowed_algorithms)
        self.required_claims = list(REQUIRED_CLAIMS)

        if audience and "aud" not in self.required_claims:
            self.required_claims.append("aud")

        # Each verifier instance owns its own JWKSCache — no cross-tenant bleed.
        effective_ttl = cache_ttl if cache_ttl is not None else JWKS_CACHE_TTL_SECONDS
        self._jwks_cache = JWKSCache(
            jwks_url=self.jwks_uri,
            cache_ttl=effective_ttl,
            timeout=JWKS_FETCH_TIMEOUT_SECONDS,
            max_retries=1,
            headers_provider=headers_provider,
        )

        logger.debug(
            f"Initialized {self.__class__.__name__} issuer={self.issuer},"
            f" jwks_host={self.jwks_host}, audience={self.audience},"
            f" allowed_algs={sorted(self.allowed_algorithms)},"
            f" cache_ttl={effective_ttl}s"
        )

    @property
    def jwks_uri(self) -> str:
        return f"{self.jwks_host}/token/.well-known/jwks.json"

    @property
    def jwks_host(self) -> str:
        return self._jwks_host

    @jwks_host.setter
    def jwks_host(self, value: str) -> None:
        self._jwks_host = value.rstrip("/")

    @property
    def issuer(self) -> str:
        return self._issuer

    @issuer.setter
    def issuer(self, value: str) -> None:
        self._issuer = value

    @abstractmethod
    async def validate(self, token: str) -> TrustedClaims:
        """Subclasses decide whether to add header/temporal enforcement."""
        raise NotImplementedError  # pragma: no cover

    def _get_unverified_header(self, token: str) -> dict[str, Any]:
        """Extract the JOSE header without verifying the signature."""
        try:
            return jwt.get_unverified_header(token)
        except PyJWTInvalidTokenError as exc:
            logger.warning(f"Failed to parse token header issuer={self.issuer}")
            raise InvalidTokenError("Invalid token format") from exc

    def _validate_algorithm(self, header: dict[str, Any]) -> None:
        """Ensure the JOSE header's alg value is on the allow-list."""
        algorithm: Any = header.get("alg")

        if algorithm not in self.allowed_algorithms:
            allowed = ", ".join(sorted(self.allowed_algorithms))
            logger.warning(
                f"Rejecting token issuer={self.issuer}, reason=algorithm_not_allowed, alg={algorithm}, allowed={allowed}"
            )
            raise AlgorithmNotAllowedError(
                f"Algorithm '{algorithm}' is not allowed. Allowed: {allowed}"
            )

    async def _get_signing_key(self, kid: str) -> Any:
        """Retrieve the parsed public key for the given kid from the unified cache."""
        return await self._jwks_cache.get_key(kid)

    def _decode_and_verify(self, token: str, key: Any) -> dict[str, Any]:
        """Use PyJWT to validate timing + issuer/audience claims."""
        options: Options = {
            "require": self.required_claims,
            "verify_exp": True,
            "verify_nbf": True,
            "verify_iss": True,
            "verify_aud": self.audience is not None,
            "verify_iat": True,
        }

        try:
            logger.info(f"Decoding token required_claims={self.required_claims}")
            return jwt.decode(
                token,
                key,
                algorithms=list(self.allowed_algorithms),
                audience=self.audience,
                issuer=self.issuer,
                options=options,
            )
        except ExpiredSignatureError as exc:
            logger.warning(
                f"Token expired issuer={self.issuer}, audience={self.audience}."
            )
            raise ExpiredTokenError("The token has expired") from exc
        except ImmatureSignatureError as exc:
            logger.warning(
                f"Token not yet valid issuer={self.issuer}, audience={self.audience}."
            )
            raise TokenNotYetValidError(
                "The token is not yet valid (nbf claim is in the future)"
            ) from exc
        except PyJWTInvalidIssuerError as exc:
            logger.warning(f"Invalid issuer detected expected={self.issuer}.")
            raise InvalidIssuerError(
                f"Token issuer does not match expected issuer '{self.issuer}'"
            ) from exc
        except PyJWTInvalidAudienceError as exc:
            logger.warning(f"Invalid audience detected expected={self.audience}.")
            raise InvalidAudienceError(
                f"Token audience does not match expected audience '{self.audience}'"
            ) from exc
        except PyJWTInvalidTokenError as exc:
            logger.warning(
                f"Generic token validation failure issuer={self.issuer}, audience={self.audience}."
            )
            raise InvalidTokenError(f"Token validation failed: {exc}") from exc

    async def _decode_and_verify_with_retry(
        self, token: str, header: dict[str, Any]
    ) -> dict[str, Any]:
        """Get the signing key from the unified cache and verify the token.

        Implements a two-scenario verification strategy:

        Scenario 1: Signing Key is present in cache
        ─────────────────────────────────────────────
        Step 1: Fetch the signing key from the in-memory cache.
        Step 2: Use it to decode and verify the token's signature and claims.
        Step 3:
            3a. If no signature/claims error:
                - Return successfully with decoded claims.
            3b. If signature/claims error occurs:
                - The key may have been rotated server-side (non-standard but possible).
                - Trigger a refresh-on-miss to fetch the latest JWKS from the server.
                - Attempt to retrieve the signing key again.
                - If the key is found and differs from the cached one:
                    - Use the new key to decode and verify the token.
                    - If this succeeds: Return successfully with decoded claims.
                    - If this fails: Raise the error (key rotation didn't fix it).
                - If the key is identical or not found:
                    - Raise the original verification error.

        Scenario 2: Signing Key is NOT present in cache
        ──────────────────────────────────────────────
        Step 1: The cache will detect the missing key and trigger a refresh-on-miss.
        Step 2: Fetch the signing key from the JWKS endpoint.
        Step 3: Use it to decode and verify the token's signature and claims.
        Step 4:
            - If signature/claims error:
                - Stop and raise an appropriate error.
            - If succeeds:
                - Update cache with the new key.
                - Return successfully with decoded claims.
        """
        header_kid: str = header.get("kid")  # type: ignore

        # First attempt: get key from cache (may trigger scheduled refresh if TTL expired,
        # or refresh-on-miss if kid is not found in the fresh cache).
        signing_key = await self._get_signing_key(header_kid)

        try:
            return self._decode_and_verify(token, signing_key)
        except (PyJWTInvalidTokenError, InvalidTokenError) as first_error:
            # Signature or claim verification failed — the key may have been
            # rotated server-side with the same kid (non-standard but possible).
            # Force a refresh-on-miss and retry exactly once.
            logger.debug(
                f"Verification failed for kid={header_kid}, triggering refresh-on-miss: {first_error}"
            )
            try:
                refreshed_key = await self._jwks_cache.get_key(header_kid)
            except SigningKeyNotFoundError:
                raise first_error from None

            # If the key object is identical, no point retrying.
            if refreshed_key is signing_key:
                raise first_error

            return self._decode_and_verify(token, refreshed_key)

    async def close(self) -> None:
        """Close the underlying JWKS cache httpx client for clean shutdown."""
        await self._jwks_cache.close()

    async def _verify_token(self, token: str) -> tuple[dict[str, Any], dict[str, Any]]:
        """Run the full verification pipeline and return the decoded pieces."""

        header: dict[str, Any] = self._get_unverified_header(token)
        logger.debug(
            f"Extracted header kid={header.get('kid')} typ={header.get('typ')} alg={header.get('alg')}"
        )

        # Apply algorithm allow-list checks before touching the JWKS cache.
        self._validate_algorithm(header)

        claims: dict[str, Any] = await self._decode_and_verify_with_retry(token, header)

        return header, claims
