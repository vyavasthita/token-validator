"""
Token Profile module.

Provides the abstract base class for token validation profiles and defines the
business-logic layer that runs after `JWTVerifier` establishes cryptographic
trust. Each profile encapsulates domain expectations (principal type, token
shape, temporal guardrails, etc.) so new token flavors can be introduced without
touching the verifier.
"""

import logging
from abc import ABC, abstractmethod
from typing import Iterable

from jwt_lib.claims import TrustedClaims
from jwt_lib.validation import ClaimValidator, ClaimRule
from jwt_lib.exceptions import InvalidClaimError


logger = logging.getLogger(__name__)


class TokenProfile(ABC):
    """
    Abstract base class for token validation profiles.

    A TokenProfile encapsulates domain-specific validation logic for a particular
    type of JWT token. This follows the Strategy Pattern, allowing different
    validation strategies to be applied after cryptographic verification.

    Subclasses should:
    1. Define expected claim values as constructor parameters
    2. Build validation rules in __init__
    3. Pass those rules to the base constructor
    4. Override validate() to orchestrate rule execution
    5. Implement any custom validation logic in _custom_validations()
    """

    def __init__(self, rules: Iterable[ClaimRule]) -> None:
        """Initialize the profile with its validation rules."""
        self._claim_validator = ClaimValidator(rules)

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
    
    @abstractmethod
    async def validate(
        self,
        claims: TrustedClaims,
        extra_rules: Iterable[ClaimRule] | None = None,
    ) -> None:
        """
        Validate claims against this profile.

        Subclasses decide how to apply rule-based and custom checks.

        Args:
            claims: The verified claims to validate.
            extra_rules: Optional additional ClaimRule instances to apply.

        Raises:
            InvalidClaimError: If a claim validation fails.
            PermissionDeniedError: If a permission check fails.
        """
        raise NotImplementedError

    @abstractmethod
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
        raise NotImplementedError

    async def _apply_extra_rules(
        self,
        claims: TrustedClaims,
        extra_rules: Iterable[ClaimRule] | None,
    ) -> None:
        """Run optional supplemental claim rules when provided."""

        if not extra_rules:
            return None

        concrete_rules: list[ClaimRule] = []
        
        for rule in extra_rules:
            if not isinstance(rule, ClaimRule):
                raise InvalidClaimError(
                    "Extra rules must inherit from ClaimRule. Received instance of "
                    f"{rule.__class__.__name__}."
                )
            concrete_rules.append(rule)

        await ClaimValidator(concrete_rules).validate(claims)
        return None