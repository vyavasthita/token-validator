"""Base infrastructure for verifying JWTs against JWKS."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any, Iterable
from collections import OrderedDict
import asyncio
import jwt
from jwt.algorithms import RSAAlgorithm
from jwt.types import Options
from jwt.exceptions import (
    ExpiredSignatureError,
    ImmatureSignatureError,
    InvalidAudienceError as PyJWTInvalidAudienceError,
    InvalidIssuerError as PyJWTInvalidIssuerError,
    InvalidTokenError as PyJWTInvalidTokenError,
)

from jwt_lib.verifier.timeout_jwk_client import AsyncJWKSFetcher
from jwt_lib.config.config import JWKS_FETCH_TIMEOUT_SECONDS, REQUIRED_CLAIMS, CACHE_MAXSIZE
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
    """
    Abstract verifier that handles the shared JWKS + PyJWT workflow.
    Implements in-memory caching of signing keys by kid, with retry logic on failure.
    """

    def __init__(
        self,
        issuer: str,
        jwks_host: str,
        allowed_algorithms: Iterable[str],
        audience: str | None = None,
    ) -> None:
        """Store verifier configuration and eagerly build the JWKS client."""
        
        self.issuer = issuer
        self.jwks_host = jwks_host
        self.audience = audience
        self.allowed_algorithms = set(allowed_algorithms)
        self.required_claims = list(REQUIRED_CLAIMS)
        # Each verifier instance keeps its own signing-key cache to avoid
        # cross-tenant bleed while still providing in-process reuse.
        self._SIGNING_KEY_CACHE: OrderedDict[str, Any] = OrderedDict()
        self._cache_lock = asyncio.Lock()

        if audience and "aud" not in self.required_claims:
            self.required_claims.append("aud")

        self._jwks_fetcher = AsyncJWKSFetcher(self.jwks_uri, timeout=JWKS_FETCH_TIMEOUT_SECONDS)

        logger.debug(
            f"Initialized {self.__class__.__name__} issuer={self.issuer}, jwks_host={self.jwks_host}, audience={self.audience}, allowed_algs={sorted(self.allowed_algorithms)}, jwks_fetch_timeout={JWKS_FETCH_TIMEOUT_SECONDS}"
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
        raise NotImplementedError

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
    
    async def _get_signing_key(self, token: str, kid: str) -> Any:
        """
        Fetch the signing key from JWKS for the given kid.
        """
        try:
            # Log the JWKS URI being fetched
            logger.debug(f"Fetching JWKS from {self.jwks_uri}")

            # Fetch the JWKS (JSON Web Key Set) from the remote endpoint asynchronously
            jwks = await self._jwks_fetcher.fetch()
            
            # Search for the JWK with the matching kid
            jwk_for_token = next((key_dict for key_dict in jwks.get("keys", []) if key_dict.get("kid") == kid), None)
            
            if jwk_for_token:
                logger.debug(f"Matching key found in JWKS for kid={kid}")

                # Convert the JWK to a public key object usable by PyJWT
                return RSAAlgorithm.from_jwk(jwk_for_token)
            
            # If no matching key is found, log and raise a custom error
            logger.warning(f"No matching key found in JWKS for kid={kid}")
            raise SigningKeyNotFoundError(f"Could not find signing key for kid={kid}")
        except SigningKeyNotFoundError:
            # Already logged upstream; just propagate for callers to translate.
            raise
        except (jwt.PyJWTError, ValueError) as exc:
            logger.exception(f"Failed to fetch signing key issuer={self.issuer}")
            raise SigningKeyNotFoundError("Could not find signing key for token") from exc

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
            logger.debug(
                f"Decoding token issuer={self.issuer}, audience={self.audience}, required_claims={self.required_claims}"
            )
            return jwt.decode(
                token,
                key,
                algorithms=list(self.allowed_algorithms),
                audience=self.audience,
                issuer=self.issuer,
                options=options,
            )
        except ExpiredSignatureError as exc:
            logger.warning(f"Token expired issuer={self.issuer}, audience={self.audience}.")
            raise ExpiredTokenError("The token has expired") from exc
        except ImmatureSignatureError as exc:
            logger.warning(f"Token not yet valid issuer={self.issuer}, audience={self.audience}.")
            raise TokenNotYetValidError(
                "The token is not yet valid (nbf claim is in the future)"
            ) from exc
        except PyJWTInvalidIssuerError as exc:
            logger.warning(
                f"Invalid issuer detected expected={self.issuer}."
            )
            raise InvalidIssuerError(
                f"Token issuer does not match expected issuer '{self.issuer}'"
            ) from exc
        except PyJWTInvalidAudienceError as exc:
            logger.warning(
                f"Invalid audience detected expected={self.audience}."
            )
            raise InvalidAudienceError(
                f"Token audience does not match expected audience '{self.audience}'"
            ) from exc
        except PyJWTInvalidTokenError as exc:
            logger.warning(f"Generic token validation failure issuer={self.issuer}, audience={self.audience}.")
            raise InvalidTokenError(f"Token validation failed: {exc}") from exc
        
    async def verify_non_cached_key(self, token: str, header_kid: str) -> dict[str, Any]:
        """Fetch a signing key from JWKS and cache it for future use."""

        signing_key: Any = await self._get_signing_key(token, header_kid)
        claims: dict[str, Any] = self._decode_and_verify(token, signing_key)

        async with self._cache_lock:
            # Evict the least-recently used key before inserting a new one to
            # keep memory bounded by CACHE_MAXSIZE.
            if len(self._SIGNING_KEY_CACHE) >= CACHE_MAXSIZE:
                logger.debug(
                    f"Evicting LRU signing key for host={self.jwks_host} to honor CACHE_MAXSIZE={CACHE_MAXSIZE}."
                )
                self._SIGNING_KEY_CACHE.popitem(last=False)

            self._SIGNING_KEY_CACHE[header_kid] = signing_key
            self._SIGNING_KEY_CACHE.move_to_end(header_kid)
        return claims
    
    async def verify_cached_key(self, token: str, header_kid: str, cached_signing_key: Any) -> dict[str, Any]:
        """Attempt verification with a cached key, refreshing LRU order on success."""

        logger.debug(f"Using cached signing key for kid={header_kid}.")

        try:
            claims = self._decode_and_verify(token, cached_signing_key)
        except (PyJWTInvalidTokenError, InvalidTokenError) as error:
            async with self._cache_lock:
                self._SIGNING_KEY_CACHE.pop(header_kid, None)
                logger.debug(
                    f"Cleared cached signing key for kid={header_kid} due to verification failure: {error}."
                )
            return await self.verify_non_cached_key(token, header_kid)
        else:
            async with self._cache_lock:
                # Refresh the entry's position so frequently used keys stay in cache longer.
                if header_kid in self._SIGNING_KEY_CACHE:
                    self._SIGNING_KEY_CACHE.move_to_end(header_kid)
            return claims
    
    async def _decode_and_verify_with_retry(self, token: str, header: dict[str, Any]) -> dict[str, Any]:
        """
        Run the full verification pipeline and return the decoded pieces

        Scenario 1: Signing Key is present in cache
            Step 1: Fetch the signing from an in-memory cache.
            Step 2: Use it to decode and verify the token's signature and claims.
            Step 3:
                3a. If no signature key error
                    - Return successfully
                3b. If signature key error
                    - Clear cache
                    - Fetch the signing key from JWKS
                    - Use it to decode and verify the token's signature and claims
                    - If signature key error
                        - Stop and raise an appropriate error.
                    - If succeeds:
                        - Update cache
                        - Return successfully

        Scenario 2: Signing Key is NOT present in cache
            - Fetch the signing key from JWKS
            - Use it to decode and verify the token's signature and claims
            - If signature key error
                - Stop and raise an appropriate error.
            - If succeeds:
                - Update cache
                - Return successfully
        """
        header_kid = header.get("kid")  # type: ignore
        async with self._cache_lock:
            cached_signing_key = self._SIGNING_KEY_CACHE.get(header_kid)  # type: ignore

        # Scenario 1: Signing Key is present in cache
        if cached_signing_key:
            logger.debug(f"Found signing key in cache for kid={header_kid}")
            claims = await self.verify_cached_key(token, header_kid, cached_signing_key)  # type: ignore
        # Scenario 2: Signing Key is NOT present in cache
        else:
            logger.debug(f"No signing key in cache for kid={header_kid}, fetching from JWKS.")
            claims = await self.verify_non_cached_key(token, header_kid)  # type: ignore
        return claims

    
    async def _verify_token(self, token: str) -> tuple[dict[str, Any], dict[str, Any]]:
        """Run the full verification pipeline and return the decoded pieces"""
        
        logger.debug(
            f"Starting verification with {self.__class__.__name__} issuer={self.issuer}, audience={self.audience}."
        )

        header: dict[str, Any] = self._get_unverified_header(token)
        logger.debug(
            f"Extracted header kid={header.get('kid')} typ={header.get('typ')} alg={header.get('alg')}"
        )
        
        # Apply algorithm allow-list checks before touching the JWKS client.
        self._validate_algorithm(header)

        claims: dict[str, Any] = await self._decode_and_verify_with_retry(token, header)

        return header, claims