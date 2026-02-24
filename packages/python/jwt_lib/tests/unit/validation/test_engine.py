"""Tests for ClaimValidator engine."""

import pytest

from jwt_lib.src.claims import TrustedClaims
from jwt_lib.src.exceptions import PermissionDeniedError, InvalidClaimError
from jwt_lib.src.validation import ClaimValidator, RequireScopes, RequireGrantType, RequireClaim


class TestClaimValidator:
    """Tests for the ClaimValidator class."""

    def test_initialization_with_rules(self):
        """Test initialization with a list of rules."""
        rules = [RequireScopes(["read:users"])]
        validator = ClaimValidator(rules)
        assert validator is not None

    def test_initialization_empty(self):
        """Test initialization with no rules."""
        validator = ClaimValidator()
        assert validator is not None

    def test_initialization_with_none(self):
        """Test initialization with None."""
        validator = ClaimValidator(None)
        assert validator is not None

    def test_validate_passes_all_rules(self):
        """Test validation passes when all rules pass."""
        validator = ClaimValidator([
            RequireScopes(["read:users"]),
            RequireGrantType("client-credentials"),
        ])
        
        claims = TrustedClaims({
            "scope": "read:users write:users",
            "gty": "client-credentials",
            "sub": "client",
        })
        
        # Should not raise
        validator.validate(claims)

    def test_validate_fails_on_first_failing_rule(self):
        """Test validation stops at first failing rule."""
        validator = ClaimValidator([
            RequireScopes(["missing:scope"]),
            RequireGrantType("client-credentials"),
        ])
        
        claims = TrustedClaims({
            "scope": "read:users",
            "gty": "client-credentials",
            "sub": "client",
        })
        
        with pytest.raises(PermissionDeniedError):
            validator.validate(claims)

    def test_validate_with_empty_rules(self):
        """Test validation passes with no rules."""
        validator = ClaimValidator([])
        claims = TrustedClaims({"sub": "user"})
        
        # Should not raise
        validator.validate(claims)

    def test_add_rule_method(self):
        """Test add_rule method adds rules dynamically."""
        validator = ClaimValidator()
        validator.add_rule(RequireScopes(["read:users"]))
        
        claims_with_scope = TrustedClaims({
            "scope": "read:users",
            "sub": "user",
        })
        claims_without_scope = TrustedClaims({"sub": "user"})
        
        # Should pass
        validator.validate(claims_with_scope)
        
        # Should fail
        with pytest.raises(PermissionDeniedError):
            validator.validate(claims_without_scope)

    def test_add_rule_returns_self_for_chaining(self):
        """Test add_rule returns self for method chaining."""
        validator = ClaimValidator()
        result = validator.add_rule(RequireScopes(["read:users"]))
        
        assert result is validator

    def test_method_chaining(self):
        """Test rules can be added via method chaining."""
        validator = (
            ClaimValidator()
            .add_rule(RequireScopes(["read:users"]))
            .add_rule(RequireGrantType("client-credentials"))
        )
        
        claims = TrustedClaims({
            "scope": "read:users",
            "gty": "client-credentials",
            "sub": "client",
        })
        
        # Should not raise
        validator.validate(claims)


class TestClaimValidatorIntegration:
    """Integration tests for ClaimValidator with real-world scenarios."""

    def test_api_access_validation(self):
        """Test typical API access validation scenario."""
        validator = ClaimValidator([
            RequireScopes(["api:read"]),
            RequireClaim("email_verified", expected_value=True),
        ])
        
        valid_claims = TrustedClaims({
            "scope": "api:read api:write",
            "email_verified": True,
            "sub": "user@example.com",
        })
        
        # Should pass
        validator.validate(valid_claims)

    def test_admin_access_validation(self):
        """Test admin access validation scenario."""
        validator = ClaimValidator([
            RequireScopes(["admin:all"]),
            RequireGrantType("client-credentials"),
            RequireClaim("role", expected_value="admin"),
        ])
        
        admin_claims = TrustedClaims({
            "scope": "admin:all",
            "gty": "client-credentials",
            "role": "admin",
            "sub": "admin-service",
        })
        
        # Should pass
        validator.validate(admin_claims)
        
        # User claims should fail
        user_claims = TrustedClaims({
            "scope": "user:read",
            "gty": "authorization_code",
            "role": "user",
            "sub": "regular-user",
        })
        
        with pytest.raises((PermissionDeniedError, InvalidClaimError)):
            validator.validate(user_claims)
