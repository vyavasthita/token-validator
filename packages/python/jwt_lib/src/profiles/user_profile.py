"""User token profile with strict header and temporal validation."""

import time
from typing import Iterable

from .token_profile import TokenProfile
from jwt_lib.src.claims import TrustedClaims
from jwt_lib.src.exceptions import InvalidClaimError
from jwt_lib.src.validation import (
    ClaimRule,
    ClaimValidator,
    RequireClaim,
    RequireClaimIn,
)
from jwt_lib.src.config.config import (
    DEFAULT_USER_AUDIENCE,
    DEFAULT_USER_ALLOWED_CONNECTION_METHODS,
    DEFAULT_USER_CLOCK_SKEW_SECONDS,
    DEFAULT_USER_HEADER_ALG,
    DEFAULT_USER_HEADER_TYP,
    DEFAULT_USER_MAX_TOKEN_AGE_SECONDS,
    DEFAULT_USER_PRINCIPAL_TYPE,
    DEFAULT_USER_PROFILE_NAME,
    DEFAULT_USER_REQUIRE_MODEL_ID,
    DEFAULT_USER_REQUIRE_WORKSPACE_ID,
    DEFAULT_USER_TOKEN_TYPE,
)


class UserTokenProfile(TokenProfile):
    """Token validation profile for user authentication tokens."""

    TOKEN_TYPE = DEFAULT_USER_TOKEN_TYPE
    PRINCIPAL_TYPE = DEFAULT_USER_PRINCIPAL_TYPE

    def __init__(self, audience: str | None = None) -> None:
        """Configure validation expectations for user tokens."""
        self.audience = audience or DEFAULT_USER_AUDIENCE
        self.allowed_connection_methods = list(DEFAULT_USER_ALLOWED_CONNECTION_METHODS)
        self.require_workspace_id = DEFAULT_USER_REQUIRE_WORKSPACE_ID
        self.require_model_id = DEFAULT_USER_REQUIRE_MODEL_ID
        self.clock_skew_seconds = DEFAULT_USER_CLOCK_SKEW_SECONDS
        self.max_token_age_seconds = DEFAULT_USER_MAX_TOKEN_AGE_SECONDS
        super().__init__(self._build_rules())

    def _build_rules(self) -> list[ClaimRule]:
        """Build validation rules for user tokens."""
        base_rules: list[ClaimRule] = [
            RequireClaim("tokenType", self.TOKEN_TYPE),
            RequireClaim("principalType", self.PRINCIPAL_TYPE),
            RequireClaim("aud", self.audience),
            RequireClaimIn("connectionMethod", self.allowed_connection_methods),
        ]

        optional_rules = [
            rule
            for cond, rule in (
                (self.require_workspace_id, RequireClaim("workspaceId")),
                (self.require_model_id, RequireClaim("modelId")),
            )
            if cond
        ]

        return base_rules + optional_rules

    def validate(
        self,
        claims: TrustedClaims,
        extra_rules: Iterable[ClaimRule] | None = None,
    ) -> None:
        self._claim_validator.validate(claims)

        if extra_rules:
            ClaimValidator(list(extra_rules)).validate(claims)

        self._custom_validations(claims)

    def _custom_validations(self, claims: TrustedClaims) -> None:
        """Apply header and temporal safety checks."""
        self._validate_headers(claims)
        self._validate_temporal_claims(claims)

    def _validate_headers(self, claims: TrustedClaims) -> None:
        headers = claims.headers
        if not headers:
            raise InvalidClaimError("Token header is missing")

        if not (kid := headers.get("kid")):
            raise InvalidClaimError("Token header must include 'kid'")

        if (typ := headers.get("typ")) != DEFAULT_USER_HEADER_TYP:
            raise InvalidClaimError(
                f"Token header typ must be '{DEFAULT_USER_HEADER_TYP}'"
            )

        if (alg := headers.get("alg")) != DEFAULT_USER_HEADER_ALG:
            raise InvalidClaimError(
                f"Token header alg must be '{DEFAULT_USER_HEADER_ALG}'"
            )

    def _validate_temporal_claims(self, claims: TrustedClaims) -> None:
        """Ensure iat, nbf, and exp remain within acceptable temporal bounds."""
        now = int(time.time())
        skew = max(self.clock_skew_seconds, 0)

        iat = claims.get("iat")

        if iat is None:
            raise InvalidClaimError("iat claim is required")
        
        # Enforce issued-at is not in the future and respects the max age policy.
        if iat > now + skew:
            raise InvalidClaimError("iat claim cannot be in the future")

        if self.max_token_age_seconds is not None:
            max_age = max(self.max_token_age_seconds, 0)

            if (now - iat) > max_age + skew:
                raise InvalidClaimError("Token exceeds the maximum allowed age")

        nbf = claims.get("nbf")
        
        if nbf is None:
            raise InvalidClaimError("nbf claim is required")
        
        # Ensure the token is not used before its not-before timestamp.
        if now + skew < nbf:
            raise InvalidClaimError("Token is not valid yet (nbf in future)")

        exp = claims.get("exp")
        if exp is None:
            raise InvalidClaimError("exp claim is required")

        # Reject tokens whose expiration has already passed.
        if now >= exp:
            raise InvalidClaimError("Token has expired")

    @property
    def profile_name(self) -> str:
        return DEFAULT_USER_PROFILE_NAME
