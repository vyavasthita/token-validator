"""
Auth0 Token Profile.

Encapsulates validation rules for Auth0-issued service tokens.
"""

import logging
from typing import Iterable

from .token_profile import TokenProfile

from jwt_lib.claims import TrustedClaims
from jwt_lib.validation import ClaimRule, RequireClaim
from jwt_lib.exceptions import InvalidClaimError
from jwt_lib.config.config import AUTH_0_GRANT_TYPE


logger = logging.getLogger(__name__)


class Auth0Profile(TokenProfile):
    """Profile for Auth0-issued service tokens."""

    def __init__(
        self,
        issuer: str,
        audience: str | None = None,
        app_name: str | None = None,
    ) -> None:
        self._issuer = issuer
        self.audience = audience
        self.expected_app_name = app_name
        self.expected_grant_type = AUTH_0_GRANT_TYPE
        
        super().__init__(self._build_rules())

        logger.info(
            f"Initialized Auth0Profile issuer={issuer}, audience={audience}, app_name={app_name}, grant_type={self.expected_grant_type}."
        )

    @property
    def profile_name(self) -> str:
        return "Auth0ServiceToken"

    @property
    def issuer(self) -> str:
        return self._issuer.rstrip("/") + "/"

    @issuer.setter
    def issuer(self, value: str) -> None:
        self._issuer = value
        
    def _build_rules(self) -> list[ClaimRule]:
        """Require core Auth0 service token claims."""
        rules: list[ClaimRule] = [RequireClaim("gty", self.expected_grant_type)]

        if self.audience:
            rules.append(RequireClaim("aud", self.audience))

        return rules

    async def _custom_validations(self, claims: TrustedClaims) -> None:
        """Validate optional app name claim."""

        if self.expected_app_name:
            actual_app: str | None = claims.get("appName")

            if actual_app != self.expected_app_name:
                logger.warning(
                    f"Rejecting Auth0 token reason=appName. Expected={self.expected_app_name}, actual={actual_app}."
                )
                raise InvalidClaimError(
                    f"Invalid appName claim: expected '{self.expected_app_name}' but found '{actual_app}'."
                )
            logger.debug(f"Auth0Profile appName={self.expected_app_name} validation successful.")
            
    async def validate(
        self,
        claims: TrustedClaims,
        extra_rules: Iterable[ClaimRule] | None = None,
    ) -> None:
        logger.info(f"Auth0Profile validating claims profile={self.profile_name}.")
        
        await self._claim_validator.validate(claims)
        
        if extra_rules:
            await self._apply_extra_rules(claims, extra_rules)
        
        await self._custom_validations(claims)