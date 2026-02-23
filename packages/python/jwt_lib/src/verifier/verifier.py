"""Verifier hierarchy for JWT tokens."""

from __future__ import annotations

import time
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
from jwt_lib.src.config.config import (
    DEFAULT_AUTH0_ALLOWED_ALGORITHMS,
    DEFAULT_USER_ALLOWED_ALGORITHMS,
    DEFAULT_USER_CLOCK_SKEW_SECONDS,
    DEFAULT_USER_HEADER_ALG,
    DEFAULT_USER_HEADER_TYP,
    DEFAULT_USER_MAX_TOKEN_AGE_SECONDS,
)
from jwt_lib.src.exceptions import (
    AlgorithmNotAllowedError,
    ExpiredTokenError,
    InvalidAudienceError,
    InvalidClaimError,
    InvalidIssuerError,
    InvalidTokenError,
    SigningKeyNotFoundError,
    TokenNotYetValidError,
)


class JWTVerifier(ABC):
    """Abstract verifier responsible for cryptographic trust establishment."""

    DEFAULT_ALLOWED_ALGORITHMS: tuple[str, ...] = ("RS256",)
    DEFAULT_REQUIRED_CLAIMS: tuple[str, ...] = ("exp", "iss", "sub")

    def __init__(
        self,
        issuer: str,
        audience: str | None = None,
        allowed_algorithms: Iterable[str] | None = None,
        required_claims: list[str] | None = None,
    ) -> None:
        self._issuer = issuer
        self.audience = audience
        self.allowed_algorithms = set(allowed_algorithms or self.DEFAULT_ALLOWED_ALGORITHMS)
        self.required_claims = list(required_claims or self.DEFAULT_REQUIRED_CLAIMS)

        if audience and "aud" not in self.required_claims:
            self.required_claims.append("aud")

        self._jwks_client = PyJWKClient(self.jwks_uri)

    async def validate(self, token: str) -> TrustedClaims:
        """Decode, verify, and return trusted claims for *token*."""
        header = self._get_unverified_header(token)
        self._validate_algorithm(header)
        self._enforce_header_rules(header)

        signing_key = self._get_signing_key(token, self._jwks_client)
        claims = self._decode_and_verify(token, signing_key)

        self._enforce_temporal_rules(claims)
        return TrustedClaims(claims, headers=header)

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
        except Exception as exc:  # pragma: no cover - PyJWT raises generic errors
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

    @abstractmethod
    def _enforce_header_rules(self, header: dict[str, Any]) -> None:
        """Subclasses validate JOSE header requirements (e.g., kid, typ)."""

    @abstractmethod
    def _enforce_temporal_rules(self, claims: dict[str, Any]) -> None:
        """Subclasses enforce issuance/expiry policies using JWT claims."""

    @property
    def jwks_uri(self) -> str:
        return f"{self.issuer.rstrip('/')}/.well-known/jwks.json"

    @property
    def issuer(self) -> str:
        return self._issuer.rstrip("/") + "/"

    @issuer.setter
    def issuer(self, value: str) -> None:
        self._issuer = value


class Auth0JWTVerifier(JWTVerifier):
    """Verifier for Auth0-issued service tokens."""

    def __init__(
        self,
        issuer: str,
        audience: str | None = None,
        allowed_algorithms: Iterable[str] | None = None,
        required_claims: list[str] | None = None,
    ) -> None:
        super().__init__(
            issuer=issuer,
            audience=audience,
            allowed_algorithms=allowed_algorithms or DEFAULT_AUTH0_ALLOWED_ALGORITHMS,
            required_claims=required_claims,
        )

    def _enforce_header_rules(self, header: dict[str, Any]) -> None:
        """Auth0 relies solely on the JOSE algorithm enforcement."""
        return None

    def _enforce_temporal_rules(self, claims: dict[str, Any]) -> None:
        """PyJWT already enforces exp/nbf for Auth0 tokens; nothing extra."""
        return None


class UserJWTVerifier(JWTVerifier):
    """Verifier for first-party user tokens with strict header + temporal rules."""

    def __init__(
        self,
        issuer: str,
        audience: str | None = None,
        allowed_algorithms: Iterable[str] | None = None,
        clock_skew_seconds: int = DEFAULT_USER_CLOCK_SKEW_SECONDS,
        max_token_age_seconds: int | None = DEFAULT_USER_MAX_TOKEN_AGE_SECONDS,
        expected_header_typ: str = DEFAULT_USER_HEADER_TYP,
        expected_header_alg: str = DEFAULT_USER_HEADER_ALG,
        require_kid: bool = True,
    ) -> None:
        super().__init__(
            issuer=issuer,
            audience=audience,
            allowed_algorithms=allowed_algorithms or DEFAULT_USER_ALLOWED_ALGORITHMS,
        )
        self.clock_skew_seconds = max(clock_skew_seconds, 0)
        self.max_token_age_seconds = (
            None if max_token_age_seconds is None else max(max_token_age_seconds, 0)
        )
        self.expected_header_typ = expected_header_typ
        self.expected_header_alg = expected_header_alg
        self.require_kid = require_kid

    def _enforce_header_rules(self, header: dict[str, Any]) -> None:
        """Ensure JOSE header exposes kid/typ/alg for user token policies."""
        # kid identifies the signing key inside the shared JWKS document.
        if self.require_kid and not header.get("kid"):
            raise InvalidClaimError("Token header must include 'kid'")

        typ = header.get("typ")
        # typ keeps Auth tokens distinct from other JWTs that share the issuer.
        if typ != self.expected_header_typ:
            raise InvalidClaimError(
                f"Token header typ must be '{self.expected_header_typ}'"
            )

        alg = header.get("alg")
        # alg ensures the JOSE header matches the configured allow-list exactly.
        if alg != self.expected_header_alg:
            raise InvalidClaimError(
                f"Token header alg must be '{self.expected_header_alg}'"
            )

    def _enforce_temporal_rules(self, claims: dict[str, Any]) -> None:
        """Apply issued-at, max-age, not-before, and expiration checks."""
        now = int(time.time())
        skew = self.clock_skew_seconds

        iat = claims.get("iat")
        # iat ensures the token was minted recently and not replayed from the far future.
        if iat is None:
            raise InvalidClaimError("iat claim is required")
        if iat > now + skew:
            raise InvalidClaimError("iat claim cannot be in the future")
        if (
            iat is not None
            and self.max_token_age_seconds is not None
            and (now - iat) > self.max_token_age_seconds + skew
        ):
            raise InvalidClaimError("Token exceeds the maximum allowed age")

        nbf = claims.get("nbf")
        # nbf prevents clients from using the token before it should become active.
        if nbf is None:
            raise InvalidClaimError("nbf claim is required")
        if now + skew < nbf:
            raise InvalidClaimError("Token is not valid yet (nbf in future)")

        exp = claims.get("exp")
        # exp bounds the lifetime; verifier enforces again for clearer error text.
        if exp is None:
            raise InvalidClaimError("exp claim is required")
        if now >= exp:
            raise InvalidClaimError("Token has expired")
