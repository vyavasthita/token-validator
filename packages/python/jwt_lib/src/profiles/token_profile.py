"""
Token Profile module.

Provides the abstract base class for token validation profiles and defines the
business-logic layer that runs after `JWTVerifier` establishes cryptographic
trust. Each profile encapsulates domain expectations (principal type, token
shape, temporal guardrails, etc.) so new token flavors can be introduced without
touching the verifier.
"""

from abc import ABC, abstractmethod
from typing import Iterable

from jwt_lib.src.claims import TrustedClaims
from jwt_lib.src.validation import ClaimValidator, ClaimRule


class TokenProfile(ABC):
    """
    Abstract base class for token validation profiles.

    A TokenProfile encapsulates domain-specific validation logic for a particular
    type of JWT token. This follows the Strategy Pattern, allowing different
    validation strategies to be applied after cryptographic verification.

    Subclasses should:
    1. Define expected claim values as constructor parameters
    2. Build validation rules in __init__
    3. Implement any custom validation logic in _custom_validations()

    Example:
        class MyTokenProfile(TokenProfile):
            def __init__(self, expected_role: str):
                self.expected_role = expected_role
                super().__init__()

            def _build_rules(self) -> list[ClaimRule]:
                return [RequireClaim("role", self.expected_role)]

    Usage:
        profile = MyTokenProfile(expected_role="admin")
        claims = await verifier.verify(token)
        profile.validate(claims)  # Raises if validation fails
    """

    def __init__(self) -> None:
        """Initialize the profile and build validation rules."""
        self._validator = ClaimValidator(self._build_rules())

    @abstractmethod
    def _build_rules(self) -> list[ClaimRule]:
        """
        Build the list of validation rules for this profile.

        Override this method to define the validation rules specific
        to this token profile.

        Returns:
            List of ClaimRule instances to apply during validation.
        """
        pass

    def validate(
        self,
        claims: TrustedClaims,
        extra_rules: Iterable[ClaimRule] | None = None,
    ) -> None:
        """
        Validate claims against this profile.

        This method applies all validation rules defined by the profile.
        Override _custom_validations() to add additional validation logic.

        Args:
            claims: The verified claims to validate.
            extra_rules: Optional additional ClaimRule instances to apply.

        Raises:
            InvalidClaimError: If a claim validation fails.
            PermissionDeniedError: If a permission check fails.
        """
        # Apply rule-based validations
        self._validator.validate(claims)

        if extra_rules:
            ClaimValidator(list(extra_rules)).validate(claims)

        # Apply any custom validations
        self._custom_validations(claims)

    def _custom_validations(self, claims: TrustedClaims) -> None:
        """
        Perform additional custom validations.

        Override this method to add validation logic that cannot be
        expressed as ClaimRule instances.

        Args:
            claims: The verified claims to validate.

        Raises:
            JWTError subclass: If validation fails.
        """
        pass  # Default: no custom validations

    @property
    def profile_name(self) -> str:
        """
        Get the human-readable name of this profile.

        Returns:
            The profile name (defaults to class name).
        """
        return self.__class__.__name__

    def __repr__(self) -> str:
        return f"<{self.profile_name}>"
