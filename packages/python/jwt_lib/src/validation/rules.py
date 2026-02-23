"""
Validation Rules module.

Provides pluggable validation rules for JWT claims validation.
Each rule implements the ClaimRule protocol.
"""

from abc import ABC, abstractmethod
from typing import Any

from jwt_lib.src.claims import TrustedClaims
from jwt_lib.src.exceptions import PermissionDeniedError, InvalidClaimError


class ClaimRule(ABC):
    """
    Abstract base class for claim validation rules.

    Implement this class to create custom validation rules that can be
    passed to ClaimValidator.
    """

    @abstractmethod
    def validate(self, claims: TrustedClaims) -> None:
        """
        Validate claims against this rule.

        Args:
            claims: The verified claims to validate.

        Raises:
            JWTError: If validation fails.
        """
        pass


class RequireScopes(ClaimRule):
    """
    Rule that requires specific scopes to be present in the token.

    The 'scope' claim is expected to be a space-separated string.
    """

    def __init__(self, scopes: list[str]) -> None:
        """
        Initialize the rule with required scopes.

        Args:
            scopes: List of scope strings that must all be present.
        """
        self.required_scopes: set[str] = set(scopes)

    def validate(self, claims: TrustedClaims) -> None:
        """
        Validate that all required scopes are present.

        Args:
            claims: The verified claims to validate.

        Raises:
            PermissionDeniedError: If any required scope is missing.
        """
        scope_value: Any = claims.get("scope", "")
        scope_str: str = scope_value if isinstance(scope_value, str) else ""
        token_scopes: set[str] = set(scope_str.split()) if scope_str else set()

        if not self.required_scopes.issubset(token_scopes):
            raise PermissionDeniedError(
                f"Missing required scopes: {', '.join(sorted(self.required_scopes - token_scopes))}"
            )


class RequireAnyScope(ClaimRule):
    """
    Rule that requires at least one of the specified scopes.
    """

    def __init__(self, scopes: list[str]) -> None:
        """
        Initialize the rule with acceptable scopes.

        Args:
            scopes: List of scope strings, at least one must be present.
        """
        self.acceptable_scopes: set[str] = set(scopes)

    def validate(self, claims: TrustedClaims) -> None:
        """
        Validate that at least one acceptable scope is present.

        Args:
            claims: The verified claims to validate.

        Raises:
            PermissionDeniedError: If none of the acceptable scopes are present.
        """
        scope_value: Any = claims.get("scope", "")
        scope_str: str = scope_value if isinstance(scope_value, str) else ""
        token_scopes: set[str] = set(scope_str.split()) if scope_str else set()

        if not (self.acceptable_scopes & token_scopes):
            raise PermissionDeniedError(
                f"Token must have at least one of: {', '.join(sorted(self.acceptable_scopes))}"
            )


class RequireGrantType(ClaimRule):
    """
    Rule that requires a specific grant type ('gty' claim).

    Useful to enforce that only client-credentials or authorization_code
    tokens are accepted.
    """

    def __init__(self, expected_grant_type: str) -> None:
        """
        Initialize the rule with expected grant type.

        Args:
            expected_grant_type: The expected value of the 'gty' claim.
        """
        self.expected: str = expected_grant_type

    def validate(self, claims: TrustedClaims) -> None:
        """
        Validate that the grant type matches.

        Args:
            claims: The verified claims to validate.

        Raises:
            InvalidClaimError: If the grant type does not match.
        """
        actual: str | None = claims.get("gty")
        
        if actual != self.expected:
            raise InvalidClaimError(
                f"Expected grant type '{self.expected}', got '{actual}'"
            )


class RequireClaim(ClaimRule):
    """
    Rule that requires a specific claim to be present and optionally match a value.
    """

    def __init__(self, claim_name: str, expected_value: Any = None) -> None:
        """
        Initialize the rule.

        Args:
            claim_name: The name of the claim that must be present.
            expected_value: If provided, the claim must equal this value.
        """
        self.claim_name: str = claim_name
        self.expected_value: Any | None = expected_value

    def validate(self, claims: TrustedClaims) -> None:
        """
        Validate that the claim is present and optionally matches the expected value.

        Args:
            claims: The verified claims to validate.

        Raises:
            InvalidClaimError: If the claim is missing or has wrong value.
        """
        if self.claim_name not in claims:
            raise InvalidClaimError(f"Required claim '{self.claim_name}' is missing")

        if self.expected_value is not None:
            actual: Any = claims.get(self.claim_name)
            if actual != self.expected_value:
                raise InvalidClaimError(
                    f"Claim '{self.claim_name}' expected '{self.expected_value}', got '{actual}'"
                )


class RequireSubject(ClaimRule):
    """
    Rule that requires the 'sub' claim to match a specific value.
    """

    def __init__(self, expected_subject: str) -> None:
        """
        Initialize the rule with expected subject.

        Args:
            expected_subject: The expected value of the 'sub' claim.
        """
        self.expected_subject: str = expected_subject

    def validate(self, claims: TrustedClaims) -> None:
        """
        Validate that the subject matches.

        Args:
            claims: The verified claims to validate.

        Raises:
            InvalidClaimError: If the subject does not match.
        """
        actual: str | None = claims.get("sub")
        if actual != self.expected_subject:
            raise InvalidClaimError(
                f"Expected subject '{self.expected_subject}', got '{actual}'"
            )


class RequireClaimIn(ClaimRule):
    """
    Rule that requires a claim value to be one of the allowed values.

    Useful for validating enumerated claims like connectionMethod, principalType, etc.
    """

    def __init__(self, claim_name: str, allowed_values: list[Any]) -> None:
        """
        Initialize the rule.

        Args:
            claim_name: The name of the claim to validate.
            allowed_values: List of acceptable values for the claim.
        """
        self.claim_name: str = claim_name
        self.allowed_values: set[Any] = set(allowed_values)

    def validate(self, claims: TrustedClaims) -> None:
        """
        Validate that the claim value is one of the allowed values.

        Args:
            claims: The verified claims to validate.

        Raises:
            InvalidClaimError: If the claim is missing or has an invalid value.
        """
        if self.claim_name not in claims:
            raise InvalidClaimError(f"Required claim '{self.claim_name}' is missing")

        actual: Any = claims.get(self.claim_name)
        if actual not in self.allowed_values:
            raise InvalidClaimError(
                f"Claim '{self.claim_name}' value '{actual}' not in allowed values: "
                f"{', '.join(str(v) for v in sorted(self.allowed_values))}"
            )
