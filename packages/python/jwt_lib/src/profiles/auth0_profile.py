"""
Auth0 Token Profile.

Encapsulates validation rules for Auth0-issued service tokens.
"""

from .token_profile import TokenProfile
from jwt_lib.src.claims import TrustedClaims
from jwt_lib.src.validation import ClaimRule, RequireClaim
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
        self.issuer = issuer.rstrip("/") + "/"
        self.audience = audience
        self.expected_app_name = app_name
        self.expected_grant_type = grant_type
        super().__init__()

    def _build_rules(self) -> list[ClaimRule]:
        """Require core Auth0 service token claims."""
        rules: list[ClaimRule] = []

        if self.expected_grant_type:
            rules.append(RequireClaim("gty", self.expected_grant_type))

        return rules

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
