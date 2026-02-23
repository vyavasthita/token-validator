"""User-specific JWT verifier with strict JOSE + temporal enforcement."""

from __future__ import annotations

import logging
import time
from typing import Iterable, cast, Any

from jwt_lib.src.claims import TrustedClaims
from jwt_lib.src.config.config import (
    DEFAULT_USER_ALLOWED_ALGORITHMS,
    DEFAULT_USER_CLOCK_SKEW_SECONDS,
    DEFAULT_USER_HEADER_ALG,
    DEFAULT_USER_HEADER_TYP,
    DEFAULT_USER_MAX_TOKEN_AGE_SECONDS,
)
from jwt_lib.src.exceptions import InvalidClaimError

from .base_verifier import JWTVerifier


NumericClaim = int | float | str
_MISSING = object()

logger = logging.getLogger(__name__)


class UserJWTVerifier(JWTVerifier):
    """Verifier for first-party user tokens with stricter temporal rules.

    Example:
        verifier = UserJWTVerifier(
            issuer="https://login.example.com/",
            jwks_host="https://login.example.com/",
            audience="my-first-party-app",
        )
        claims = await verifier.validate(encoded_token)
    """

    DEFAULT_ALLOWED_ALGORITHMS = DEFAULT_USER_ALLOWED_ALGORITHMS

    def __init__(
        self,
        issuer: str,
        jwks_host: str,
        audience: str | None = None,
        allowed_algorithms: Iterable[str] | None = None,
        clock_skew_seconds: int = DEFAULT_USER_CLOCK_SKEW_SECONDS,
        max_token_age_seconds: int | None = DEFAULT_USER_MAX_TOKEN_AGE_SECONDS,
        expected_header_typ: str = DEFAULT_USER_HEADER_TYP,
        expected_header_alg: str = DEFAULT_USER_HEADER_ALG,
        require_kid: bool = True,
    ) -> None:
        """Capture policy toggles (clock skew, JOSE expectations, etc.)."""
        super().__init__(
            issuer=issuer,
            jwks_host=jwks_host,
            audience=audience,
            allowed_algorithms=allowed_algorithms,
        )
        self.clock_skew_seconds = max(clock_skew_seconds, 0)
        self.max_token_age_seconds = (
            None if max_token_age_seconds is None else max(max_token_age_seconds, 0)
        )
        self.expected_header_typ = expected_header_typ
        self.expected_header_alg = expected_header_alg
        self.require_kid = require_kid

    async def validate(self, token: str) -> TrustedClaims:
        """Run JOSE + temporal enforcement after base cryptographic checks."""
        logger.debug(
            "UserJWTVerifier validating token issuer=%s audience=%s",
            self.issuer,
            self.audience,
        )
        header: dict[str, Any]
        claims: dict[str, Any]
        header, claims = await self._verify_token(token)
        self._enforce_header_rules(header)
        self._enforce_temporal_rules(claims)
        logger.debug(
            "UserJWTVerifier succeeded issuer=%s audience=%s",
            self.issuer,
            self.audience,
        )
        return TrustedClaims(claims, headers=header)

    def _enforce_header_rules(self, header: dict[str, object]) -> None:
        """Ensure the JOSE header exposes kid/typ/alg per user-token policy.

        Header validations are intentionally strict so that user tokens cannot
        masquerade as other JWTs that share the same issuer. Each check is kept
        granular to produce actionable error messages for callers.
        """
        # kid identifies the exact signing key in the shared JWKS document.
        logger.debug("Enforcing header rules expected_typ=%s expected_alg=%s", self.expected_header_typ, self.expected_header_alg)
        if self.require_kid and not header.get("kid"):
            logger.warning("Rejecting token issuer=%s reason=missing_kid", self.issuer)
            raise InvalidClaimError("Token header must include 'kid'")

        # typ guards against accidentally accepting tokens minted for other flows.
        typ: object | None = header.get("typ")
        if typ != self.expected_header_typ:
            logger.warning(
                "Rejecting token issuer=%s reason=header_typ_mismatch actual_typ=%s",
                self.issuer,
                typ,
            )
            raise InvalidClaimError(
                f"Token header typ must be '{self.expected_header_typ}'"
            )

        # alg must match the allow-list exactly to prevent downgrade attacks.
        alg: object | None = header.get("alg")
        if alg != self.expected_header_alg:
            logger.warning(
                "Rejecting token issuer=%s reason=header_alg_mismatch actual_alg=%s",
                self.issuer,
                alg,
            )
            raise InvalidClaimError(
                f"Token header alg must be '{self.expected_header_alg}'"
            )

    def _enforce_temporal_rules(self, claims: dict[str, object]) -> None:
        """Apply issued-at, max-age, not-before, and expiration checks.

        The checks mirror common IdP recommendations but keep error messages in
        the domain language of consuming services.
        """
        logger.debug(
            "Enforcing temporal rules clock_skew=%s max_age=%s",
            self.clock_skew_seconds,
            self.max_token_age_seconds,
        )
        now: int = int(time.time())
        skew: int = self.clock_skew_seconds

        # iat confirms the token was minted recently and not in the future.
        iat_source: Any = claims.get("iat", _MISSING)
        try:
            iat: int = int(cast(NumericClaim, iat_source))
        except (TypeError, ValueError) as exc:
            if iat_source is _MISSING:
                logger.warning("Rejecting token issuer=%s reason=missing_iat", self.issuer)
                raise InvalidClaimError("iat claim is required") from exc
            logger.warning("Rejecting token issuer=%s reason=non_numeric_iat", self.issuer)
            raise InvalidClaimError("iat claim must be numeric") from exc
        if iat > now + skew:
            logger.warning("Rejecting token issuer=%s reason=iat_in_future", self.issuer)
            raise InvalidClaimError("iat claim cannot be in the future")
        # max-token-age clamps how long the token can circulate after issuance.
        if (
            self.max_token_age_seconds is not None
            and (now - iat) > self.max_token_age_seconds + skew
        ):
            logger.warning("Rejecting token issuer=%s reason=token_too_old", self.issuer)
            raise InvalidClaimError("Token exceeds the maximum allowed age")

        # nbf prevents use before the token becomes active.
        nbf_source: Any = claims.get("nbf", _MISSING)
        try:
            nbf: int = int(cast(NumericClaim, nbf_source))
        except (TypeError, ValueError) as exc:
            if nbf_source is _MISSING:
                logger.warning("Rejecting token issuer=%s reason=missing_nbf", self.issuer)
                raise InvalidClaimError("nbf claim is required") from exc
            logger.warning("Rejecting token issuer=%s reason=non_numeric_nbf", self.issuer)
            raise InvalidClaimError("nbf claim must be numeric") from exc
        if now + skew < nbf:
            logger.warning("Rejecting token issuer=%s reason=nbf_in_future", self.issuer)
            raise InvalidClaimError("Token is not valid yet (nbf in future)")

        # exp bounds the token lifetime and is the final line of defense.
        exp_source: Any = claims.get("exp", _MISSING)
        try:
            exp: int = int(cast(NumericClaim, exp_source))
        except (TypeError, ValueError) as exc:
            if exp_source is _MISSING:
                logger.warning("Rejecting token issuer=%s reason=missing_exp", self.issuer)
                raise InvalidClaimError("exp claim is required") from exc
            logger.warning("Rejecting token issuer=%s reason=non_numeric_exp", self.issuer)
            raise InvalidClaimError("exp claim must be numeric") from exc
        if now >= exp:
            logger.warning("Rejecting token issuer=%s reason=token_expired", self.issuer)
            raise InvalidClaimError("Token has expired")
