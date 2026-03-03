"""User-specific JWT verifier with strict JOSE + temporal enforcement."""

from __future__ import annotations

import logging
import time
from typing import cast, Any

from .base_verifier import JWTVerifier

from jwt_lib.claims import TrustedClaims
from jwt_lib.config.config import (
    USER_ALLOWED_ALGORITHMS,
    USER_CLOCK_SKEW_SECONDS,
    USER_HEADER_ALG,
    USER_HEADER_TYP,
    USER_MAX_TOKEN_AGE_SECONDS,
)
from jwt_lib.exceptions import InvalidClaimError


NumericClaim = int | float | str
_MISSING = object()

logger = logging.getLogger(__name__)


class UserJWTVerifier(JWTVerifier):
    """Verifier for first-party user tokens with stricter temporal rules."""

    def __init__(
        self,
        issuer: str,
        jwks_host: str,
        audience: str,
    ) -> None:
        """Capture policy toggles (clock skew, JOSE expectations, etc.)."""
        super().__init__(
            issuer=issuer,
            jwks_host=jwks_host,
            audience=audience,
            allowed_algorithms=USER_ALLOWED_ALGORITHMS,
        )
        self.clock_skew_seconds = max(USER_CLOCK_SKEW_SECONDS, 0)
        self.max_token_age_seconds = (
            None if USER_MAX_TOKEN_AGE_SECONDS is None else max(USER_MAX_TOKEN_AGE_SECONDS, 0)
        )
        self.expected_header_typ = USER_HEADER_TYP
        self.expected_header_alg = USER_HEADER_ALG

    def _check_header_kid(self, header: dict[str, object]) -> None:
        """
        Ensure the JWT header contains a 'kid' (Key ID) field.
        Raises InvalidClaimError if missing.
        """
        if not header.get("kid"):
            logger.warning(f"Rejecting token issuer={self.issuer} reason=missing_kid")
            raise InvalidClaimError("Token header must include 'kid'")

    def _check_header_typ(self, header: dict[str, object]) -> None:
        """
        Ensure the JWT header 'typ' (type) matches the expected value.
        Raises InvalidClaimError if it does not match.
        """
        if (typ := header.get("typ")) != self.expected_header_typ:
            logger.warning(
                f"Rejecting token issuer={self.issuer} reason=header_typ_mismatch actual_typ={typ}"
            )
            raise InvalidClaimError(
                f"Token header typ must be '{self.expected_header_typ}'"
            )

    def _check_header_alg(self, header: dict[str, object]) -> None:
        """
        Ensure the JWT header 'alg' (algorithm) matches the expected value.
        Raises InvalidClaimError if it does not match.
        """
        if (alg := header.get("alg")) != self.expected_header_alg:
            logger.warning(
                f"Rejecting token issuer={self.issuer} reason=header_alg_mismatch actual_alg={alg}"
            )
            raise InvalidClaimError(
                f"Token header alg must be '{self.expected_header_alg}'"
            )
        
    def _check_iat(self, claims: dict[str, object], now: int, skew: int) -> int:
        """
        Validate the 'iat' (issued at) claim:
        - Must be present and numeric.
        - Must not be in the future (with skew).
        Returns the parsed iat value.
        Raises InvalidClaimError if invalid.
        """
        iat_source: Any = claims.get("iat", _MISSING)
        
        try:
            iat: int = int(cast(NumericClaim, iat_source))
        except (TypeError, ValueError) as exc:
            if iat_source is _MISSING:
                logger.warning(f"Rejecting token issuer={self.issuer} reason=missing_iat")
                raise InvalidClaimError("iat claim is required") from exc
            logger.warning(f"Rejecting token issuer={self.issuer} reason=non_numeric_iat")
            raise InvalidClaimError("iat claim must be numeric") from exc
        
        if iat > now + skew:
            logger.warning(f"Rejecting token issuer={self.issuer} reason=iat_in_future")
            raise InvalidClaimError("iat claim cannot be in the future")
        
        return iat

    def _check_max_token_age(self, iat: int, now: int, skew: int) -> None:
        """
        Enforce a maximum token age policy:
        - Checks that the token's issued-at time (iat) is not too far in the past compared to now.
        - Uses the configured max_token_age_seconds and allows for clock skew.
        Raises InvalidClaimError if the token is too old.
        """
        if (
            self.max_token_age_seconds is not None
            and (now - iat) > self.max_token_age_seconds + skew
        ):
            logger.warning(f"Rejecting token issuer={self.issuer} reason=token_too_old")
            raise InvalidClaimError("Token exceeds the maximum allowed age")

    def _check_nbf(self, claims: dict[str, object], now: int, skew: int) -> None:
        """
        Validate the 'nbf' (not before) claim:
        - Must be present and numeric.
        - Token is not valid before this time (with skew).
        Raises InvalidClaimError if invalid or not yet valid.
        """
        nbf_source: Any = claims.get("nbf", _MISSING)
        try:
            nbf: int = int(cast(NumericClaim, nbf_source))
        except (TypeError, ValueError) as exc:
            if nbf_source is _MISSING:
                logger.warning(f"Rejecting token issuer={self.issuer} reason=missing_nbf")
                raise InvalidClaimError("nbf claim is required") from exc
            logger.warning(f"Rejecting token issuer={self.issuer} reason=non_numeric_nbf")
            raise InvalidClaimError("nbf claim must be numeric") from exc
        
        if now + skew < nbf:
            logger.warning(f"Rejecting token issuer={self.issuer} reason=nbf_in_future")
            raise InvalidClaimError("Token is not valid yet (nbf in future)")

    def _check_exp(self, claims: dict[str, object], now: int) -> None:
        """
        Validate the 'exp' (expiration) claim:
        - Must be present and numeric.
        - Token is invalid after this time.
        Raises InvalidClaimError if expired or invalid.
        """
        exp_source: Any = claims.get("exp", _MISSING)

        try:
            exp: int = int(cast(NumericClaim, exp_source))
        except (TypeError, ValueError) as exc:
            if exp_source is _MISSING:
                logger.warning(f"Rejecting token issuer={self.issuer} reason=missing_exp")
                raise InvalidClaimError("exp claim is required") from exc
            
            logger.warning(f"Rejecting token issuer={self.issuer} reason=non_numeric_exp")
            raise InvalidClaimError("exp claim must be numeric") from exc
        
        if now >= exp:
            logger.warning(f"Rejecting token issuer={self.issuer} reason=token_expired")
            raise InvalidClaimError("Token has expired")
        
    async def validate(self, token: str) -> TrustedClaims:
        """Run JOSE + temporal enforcement after base cryptographic checks."""

        logger.debug(
            f"UserJWTVerifier validating token issuer={self.issuer}, audience={self.audience}"
        )
        header: dict[str, Any]
        claims: dict[str, Any]

        header, claims = await self._verify_token(token)

        # Ensure the JOSE header exposes kid/typ/alg per user-token policy.
        logger.debug(f"Enforcing header rules expected_typ={self.expected_header_typ}, expected_alg={self.expected_header_alg}")
        self._check_header_kid(header)  # kid must be present
        self._check_header_typ(header) 
        self._check_header_alg(header)

        # Apply issued-at, max-age, not-before, and expiration checks etc
        logger.debug(
            f"Enforcing temporal rules clock_skew={self.clock_skew_seconds}, max_age={self.max_token_age_seconds}"
        )
        now: int = int(time.time())
        skew: int = self.clock_skew_seconds

        iat = self._check_iat(claims, now, skew)
        self._check_max_token_age(iat, now, skew)
        self._check_nbf(claims, now, skew)
        self._check_exp(claims, now)
        
        logger.debug(
            f"UserJWTVerifier succeeded issuer={self.issuer}, audience={self.audience}"
        )
        return TrustedClaims(claims, headers=header)