"""Base infrastructure for verifying JWTs against JWKS."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any, Iterable

import jwt
from jwt import PyJWKClient
from jwt.exceptions import (
    ExpiredSignatureError,
    ImmatureSignatureError,
    InvalidAudienceError as PyJWTInvalidAudienceError,
    InvalidIssuerError as PyJWTInvalidIssuerError,
    InvalidTokenError as PyJWTInvalidTokenError,
)
from jwt.types import Options

from jwt_lib.src.claims import TrustedClaims
from jwt_lib.src.exceptions import (
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

    Example:
        class ServiceVerifier(JWTVerifier):
            async def validate(self, token: str) -> TrustedClaims:
                header, claims = await self._verify_token(token)
                return TrustedClaims(claims, headers=header)
    """

    DEFAULT_ALLOWED_ALGORITHMS: tuple[str, ...] = ("RS256",)
    DEFAULT_REQUIRED_CLAIMS: tuple[str, ...] = ("exp", "iss", "sub")

    def __init__(
        self,
        issuer: str,
        jwks_host: str,
        audience: str | None = None,
        allowed_algorithms: Iterable[str] | None = None,
        required_claims: list[str] | None = None,
    ) -> None:
        """Store verifier configuration and eagerly build the JWKS client."""
        self.issuer = issuer
        self.jwks_host = jwks_host
        self.audience = audience
        self.allowed_algorithms = set(allowed_algorithms or self.DEFAULT_ALLOWED_ALGORITHMS)
        self.required_claims = list(required_claims or self.DEFAULT_REQUIRED_CLAIMS)

        if audience and "aud" not in self.required_claims:
            self.required_claims.append("aud")

        self._jwks_client = PyJWKClient(self.jwks_uri)
        logger.debug(
            "Initialized %s issuer=%s jwks_host=%s audience=%s allowed_algs=%s",
            self.__class__.__name__,
            self.issuer,
            self.jwks_host,
            self.audience,
            sorted(self.allowed_algorithms),
        )

    @abstractmethod
    async def validate(self, token: str) -> TrustedClaims:
        """Subclasses decide whether to add header/temporal enforcement."""
        raise NotImplementedError

    async def _verify_token(self, token: str) -> tuple[dict[str, Any], dict[str, Any]]:
        """Run the full verification pipeline and return the decoded pieces."""
        logger.debug(
            "Starting verification with %s issuer=%s",
            self.__class__.__name__,
            self.issuer,
        )
        header: dict[str, Any] = self._get_unverified_header(token)
        logger.debug(
            "Extracted header kid=%s typ=%s alg=%s",
            header.get("kid"),
            header.get("typ"),
            header.get("alg"),
        )
        # Apply algorithm allow-list checks before touching the JWKS client.
        self._validate_algorithm(header)
        # Fetch the signing key via JWKS and decode with PyJWT.
        signing_key: Any = self._get_signing_key(token, self._jwks_client)
        claims: dict[str, Any] = self._decode_and_verify(token, signing_key)
        logger.debug(
            "Token verification succeeded issuer=%s audience=%s",
            self.issuer,
            self.audience,
        )
        return header, claims

    def _get_unverified_header(self, token: str) -> dict[str, Any]:
        """Extract the JOSE header without verifying the signature."""
        try:
            return jwt.get_unverified_header(token)
        except PyJWTInvalidTokenError as exc:
            logger.warning("Failed to parse token header issuer=%s", self.issuer)
            raise InvalidTokenError("Invalid token format") from exc

    def _validate_algorithm(self, header: dict[str, Any]) -> None:
        """Ensure the JOSE header's alg value is on the allow-list."""
        algorithm: Any = header.get("alg")
        if algorithm not in self.allowed_algorithms:
            allowed = ", ".join(sorted(self.allowed_algorithms))
            logger.warning(
                "Rejecting token issuer=%s reason=algorithm_not_allowed alg=%s allowed=%s",
                self.issuer,
                algorithm,
                allowed,
            )
            raise AlgorithmNotAllowedError(
                f"Algorithm '{algorithm}' is not allowed. Allowed: {allowed}"
            )

    def _get_signing_key(self, token: str, jwks_client: PyJWKClient) -> Any:
        """Load the public key that was used to sign *token* from JWKS."""
        try:
            logger.debug("Fetching signing key from %s", self.jwks_uri)
            signing_key = jwks_client.get_signing_key_from_jwt(token)
            return signing_key.key
        except Exception as exc:  # pragma: no cover - pyjwt raises generic errors
            logger.exception("Failed to fetch signing key issuer=%s", self.issuer)
            raise SigningKeyNotFoundError("Could not find signing key for token") from exc

    def _decode_and_verify(self, token: str, key: Any) -> dict[str, Any]:
        """Use PyJWT to validate timing + issuer/audience claims."""
        options: Options = {
            "require": self.required_claims,
            "verify_exp": True,
            "verify_nbf": True,
            "verify_iss": True,
            "verify_aud": self.audience is not None,
            "verify_iat": False,
        }

        try:
            logger.debug(
                "Decoding token issuer=%s audience=%s required_claims=%s",
                self.issuer,
                self.audience,
                self.required_claims,
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
            logger.warning("Token expired issuer=%s audience=%s", self.issuer, self.audience)
            raise ExpiredTokenError("The token has expired") from exc
        except ImmatureSignatureError as exc:
            logger.warning("Token not yet valid issuer=%s audience=%s", self.issuer, self.audience)
            raise TokenNotYetValidError(
                "The token is not yet valid (nbf claim is in the future)"
            ) from exc
        except PyJWTInvalidIssuerError as exc:
            logger.warning(
                "Invalid issuer detected expected=%s", self.issuer
            )
            raise InvalidIssuerError(
                f"Token issuer does not match expected issuer '{self.issuer}'"
            ) from exc
        except PyJWTInvalidAudienceError as exc:
            logger.warning(
                "Invalid audience detected expected=%s", self.audience
            )
            raise InvalidAudienceError(
                f"Token audience does not match expected audience '{self.audience}'"
            ) from exc
        except PyJWTInvalidTokenError as exc:
            logger.warning("Generic token validation failure issuer=%s", self.issuer)
            raise InvalidTokenError(f"Token validation failed: {exc}") from exc

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
