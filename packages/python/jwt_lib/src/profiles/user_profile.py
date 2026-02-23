"""User token profile that focuses on business-specific claims."""

import logging
from typing import Iterable

from .token_profile import TokenProfile
from jwt_lib.src.claims import TrustedClaims
from jwt_lib.src.validation import (
    ClaimRule,
    RequireClaim,
    RequireClaimIn,
)
from jwt_lib.src.config.config import (
    DEFAULT_USER_ALLOWED_CONNECTION_METHODS,
    DEFAULT_USER_PRINCIPAL_TYPE,
    DEFAULT_USER_PROFILE_NAME,
    DEFAULT_USER_TOKEN_TYPE,
)

logger = logging.getLogger(__name__)


class UserProfile(TokenProfile):
    """Token validation profile for user authentication tokens."""

    TOKEN_TYPE = DEFAULT_USER_TOKEN_TYPE
    PRINCIPAL_TYPE = DEFAULT_USER_PRINCIPAL_TYPE

    def __init__(self, issuer: str, audience: str | None = None) -> None:
        """Configure validation expectations for user tokens."""
        self.issuer = issuer
        self.audience = audience

        super().__init__(self._build_rules())
        logger.debug(
            "Initialized UserProfile issuer=%s audience=%s", self.issuer, self.audience
        )

    def _build_rules(self) -> list[ClaimRule]:
        """Build validation rules for user tokens."""
        rules: list[ClaimRule] = [
            RequireClaim("tokenType", self.TOKEN_TYPE),
            RequireClaim("principalType", self.PRINCIPAL_TYPE),
            RequireClaim("iss", self.issuer),
            RequireClaimIn("connectionMethod", list(DEFAULT_USER_ALLOWED_CONNECTION_METHODS)),
        ]

        if self.audience:
            rules.append(RequireClaim("aud", self.audience))

        return rules

    def validate(
        self,
        claims: TrustedClaims,
        extra_rules: Iterable[ClaimRule] | None = None,
    ) -> None:
        logger.debug("UserProfile validating claims profile=%s", self.profile_name)
        self._claim_validator.validate(claims)
        self._apply_extra_rules(claims, extra_rules)

        self._custom_validations(claims)
        logger.debug("UserProfile validation complete profile=%s", self.profile_name)

    def _custom_validations(self, claims: TrustedClaims) -> None:
        """No-op: JWT verifier enforces JOSE + temporal contracts."""
        return None

    @property
    def profile_name(self) -> str:
        return DEFAULT_USER_PROFILE_NAME
