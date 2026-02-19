"""
Auth0 Token Profile.

Encapsulates validation rules for Auth0-issued service tokens.
"""

from typing import Iterable

from .token_profile import TokenProfile
from jwt_lib.src.claims import TrustedClaims
from jwt_lib.src.validation import ClaimRule, ClaimValidator, RequireClaim
from jwt_lib.src.exceptions import InvalidClaimError


class Auth0Profile(TokenProfile):
    """Profile for Auth0-issued service tokens."""

    def __init__(
        self,
        issuer: str,
        audience: str | None = None,
        app_name: str | None = None,
        grant_type: str = "client-credentials",
    ) -> None:
        self._issuer = issuer
        self.audience = audience
        self.expected_app_name = app_name
        self.expected_grant_type = grant_type
        
        super().__init__(self._build_rules())

    def _build_rules(self) -> list[ClaimRule]:
        """Require core Auth0 service token claims."""
        return [RequireClaim("gty", self.expected_grant_type)] if self.expected_grant_type else []

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
        """Validate optional app name claim."""
        if self.expected_app_name:
            actual_app = claims.get("appName")
            
            if actual_app != self.expected_app_name:
                raise InvalidClaimError(
                    f"Invalid appName claim: expected '{self.expected_app_name}' but found '{actual_app}'."
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
