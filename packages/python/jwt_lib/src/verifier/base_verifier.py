"""Base infrastructure for verifying JWTs against JWKS."""

from __future__ import annotations

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


class JWTVerifier(ABC):
    """Abstract verifier that handles cryptographic validation plumbing."""

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
        self.issuer = issuer
        self.jwks_host = jwks_host
        self.audience = audience
        self.allowed_algorithms = set(allowed_algorithms or self.DEFAULT_ALLOWED_ALGORITHMS)
        self.required_claims = list(required_claims or self.DEFAULT_REQUIRED_CLAIMS)

        if audience and "aud" not in self.required_claims:
            self.required_claims.append("aud")

        self._jwks_client = PyJWKClient(self.jwks_uri)

    @abstractmethod
    async def validate(self, token: str) -> TrustedClaims:
        """Subclasses decide whether to add header/temporal enforcement."""
        raise NotImplementedError

    async def _verify_token(self, token: str) -> tuple[dict[str, Any], dict[str, Any]]:
        """Decode and cryptographically verify *token*, returning header and claims."""
        header = self._get_unverified_header(token)
        self._validate_algorithm(header)
        signing_key = self._get_signing_key(token, self._jwks_client)
        claims = self._decode_and_verify(token, signing_key)
        return header, claims

    def _get_unverified_header(self, token: str) -> dict[str, Any]:
        try:
            return jwt.get_unverified_header(token)
        except PyJWTInvalidTokenError as exc:
            raise InvalidTokenError("Invalid token format") from exc

    def _validate_algorithm(self, header: dict[str, Any]) -> None:
        algorithm = header.get("alg")
        if algorithm not in self.allowed_algorithms:
            allowed = ", ".join(sorted(self.allowed_algorithms))
            raise AlgorithmNotAllowedError(
                f"Algorithm '{algorithm}' is not allowed. Allowed: {allowed}"
            )

    def _get_signing_key(self, token: str, jwks_client: PyJWKClient) -> Any:
        try:
            signing_key = jwks_client.get_signing_key_from_jwt(token)
            return signing_key.key
        except Exception as exc:  # pragma: no cover - pyjwt raises generic errors
            raise SigningKeyNotFoundError("Could not find signing key for token") from exc

    def _decode_and_verify(self, token: str, key: Any) -> dict[str, Any]:
        options: Options = {
            "require": self.required_claims,
            "verify_exp": True,
            "verify_nbf": True,
            "verify_iss": True,
            "verify_aud": self.audience is not None,
            "verify_iat": False,
        }

        try:
            return jwt.decode(
                token,
                key,
                algorithms=list(self.allowed_algorithms),
                audience=self.audience,
                issuer=self.issuer,
                options=options,
            )
        except ExpiredSignatureError as exc:
            raise ExpiredTokenError("The token has expired") from exc
        except ImmatureSignatureError as exc:
            raise TokenNotYetValidError(
                "The token is not yet valid (nbf claim is in the future)"
            ) from exc
        except PyJWTInvalidIssuerError as exc:
            raise InvalidIssuerError(
                f"Token issuer does not match expected issuer '{self.issuer}'"
            ) from exc
        except PyJWTInvalidAudienceError as exc:
            raise InvalidAudienceError(
                f"Token audience does not match expected audience '{self.audience}'"
            ) from exc
        except PyJWTInvalidTokenError as exc:
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
