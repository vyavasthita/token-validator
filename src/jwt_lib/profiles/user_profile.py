"""User token profile that focuses on business-specific claims."""

import logging
from typing import Iterable

from .token_profile import TokenProfile

from jwt_lib.claims import TrustedClaims
from jwt_lib.validation import (
    ClaimRule,
    RequireClaim,
    RequireClaimIn,
)
from jwt_lib.config.config import (
    USER_ALLOWED_CONNECTION_METHODS,
    USER_PRINCIPAL_TYPE,
    USER_PROFILE_NAME,
    USER_TOKEN_TYPE,
)


logger = logging.getLogger(__name__)


class UserProfile(TokenProfile):
    """Token validation profile for user authentication tokens."""

    def __init__(self, issuer: str, audience: str | None = None) -> None:
        """Configure validation expectations for user tokens."""
        self.issuer = issuer
        self.audience = audience

        super().__init__(self._build_rules())
        
        logger.debug(
            f"Initialized UserProfile issuer={self.issuer}, audience={self.audience}."
        )

    @property
    def profile_name(self) -> str:
        return USER_PROFILE_NAME
    
    def _build_rules(self) -> list[ClaimRule]:
        """Build validation rules for user tokens."""

        rules: list[ClaimRule] = [
            RequireClaim("tokenType", USER_TOKEN_TYPE),
            RequireClaim("principalType", USER_PRINCIPAL_TYPE),
            RequireClaim("iss", self.issuer),
            RequireClaimIn("connectionMethod", list(USER_ALLOWED_CONNECTION_METHODS)),
        ]

        if self.audience:
            rules.append(RequireClaim("aud", self.audience))

        return rules

    async def validate(
        self,
        claims: TrustedClaims,
        extra_rules: Iterable[ClaimRule] | None = None,
    ) -> None:
        logger.info(f"UserProfile validating claims profile={self.profile_name}.")

        await self._claim_validator.validate(claims)
        if extra_rules:
            await self._apply_extra_rules(claims, extra_rules)
        await self._custom_validations(claims)

    async def _custom_validations(self, claims: TrustedClaims) -> None:
        """No-op: JWT verifier enforces JOSE + temporal contracts."""
        return None