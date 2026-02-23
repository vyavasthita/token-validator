"""
Validation Engine module.

Provides the ClaimValidator class that executes validation rules against claims.
"""

from typing import Iterable

from jwt_lib.src.claims import TrustedClaims
from jwt_lib.src.validation.rules import ClaimRule


class ClaimValidator:
    """
    Executes a collection of ClaimRule objects against TrustedClaims.

    This class provides a way to compose multiple validation rules and
    execute them in sequence. If any rule fails, an exception is raised.

    Example:
        validator = ClaimValidator([
            RequireScopes(["read:users"]),
            RequireGrantType("client-credentials"),
        ])
        validator.validate(claims)  # Raises if validation fails
    """

    def __init__(self, rules: Iterable[ClaimRule] | None = None) -> None:
        """
        Initialize the validator with a list of rules.

        Args:
            rules: Iterable of ClaimRule objects to execute during validation.
        """
        self._rules: list[ClaimRule] = list(rules or [])

    def add_rule(self, rule: ClaimRule) -> "ClaimValidator":
        """
        Add a rule to the validator.

        Args:
            rule: The ClaimRule to add.

        Returns:
            Self, for method chaining.
        """
        self._rules.append(rule)
        return self

    def validate(self, claims: TrustedClaims) -> None:
        """
        Execute all rules against the provided claims.

        Rules are executed in order. The first rule to fail will raise
        an exception, preventing subsequent rules from running.

        Args:
            claims: The verified claims to validate.

        Raises:
            JWTError: If any rule fails validation.
        """
        for rule in self._rules:
            active_rule: ClaimRule = rule
            active_rule.validate(claims)
