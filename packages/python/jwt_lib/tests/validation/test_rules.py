"""Tests for validation rules."""

import pytest

from jwt_lib.src.claims import TrustedClaims
from jwt_lib.src.exceptions import PermissionDeniedError, InvalidClaimError
from jwt_lib.src.validation import (
    RequireScopes,
    RequireAnyScope,
    RequireGrantType,
    RequireClaim,
    RequireSubject,
)


class TestRequireScopes:
    """Tests for RequireScopes rule."""

    def test_passes_when_all_scopes_present(self):
        """Test validation passes when all required scopes are present."""
        rule = RequireScopes(["read:users", "write:users"])
        claims = TrustedClaims({
            "scope": "read:users write:users admin",
            "sub": "user",
        })
        
        # Should not raise
        rule.validate(claims)

    def test_fails_when_scope_missing(self):
        """Test validation fails when a required scope is missing."""
        rule = RequireScopes(["read:users", "write:users"])
        claims = TrustedClaims({
            "scope": "read:users",
            "sub": "user",
        })
        
        with pytest.raises(PermissionDeniedError) as exc_info:
            rule.validate(claims)
        
        assert "write:users" in str(exc_info.value)

    def test_fails_when_no_scope_claim(self):
        """Test validation fails when scope claim is missing."""
        rule = RequireScopes(["read:users"])
        claims = TrustedClaims({"sub": "user"})
        
        with pytest.raises(PermissionDeniedError):
            rule.validate(claims)

    def test_passes_with_empty_requirements(self):
        """Test validation passes with empty required scopes."""
        rule = RequireScopes([])
        claims = TrustedClaims({"sub": "user"})
        
        # Should not raise
        rule.validate(claims)


class TestRequireAnyScope:
    """Tests for RequireAnyScope rule."""

    def test_passes_when_at_least_one_scope_present(self):
        """Test validation passes when at least one scope is present."""
        rule = RequireAnyScope(["read:users", "write:users"])
        claims = TrustedClaims({
            "scope": "read:users admin",
            "sub": "user",
        })
        
        # Should not raise
        rule.validate(claims)

    def test_fails_when_no_acceptable_scope_present(self):
        """Test validation fails when no acceptable scope is present."""
        rule = RequireAnyScope(["read:users", "write:users"])
        claims = TrustedClaims({
            "scope": "admin",
            "sub": "user",
        })
        
        with pytest.raises(PermissionDeniedError) as exc_info:
            rule.validate(claims)
        
        assert "read:users" in str(exc_info.value) or "write:users" in str(exc_info.value)

    def test_fails_when_no_scope_claim(self):
        """Test validation fails when scope claim is missing."""
        rule = RequireAnyScope(["read:users"])
        claims = TrustedClaims({"sub": "user"})
        
        with pytest.raises(PermissionDeniedError):
            rule.validate(claims)


class TestRequireGrantType:
    """Tests for RequireGrantType rule."""

    def test_passes_when_grant_type_matches(self):
        """Test validation passes when grant type matches."""
        rule = RequireGrantType("client-credentials")
        claims = TrustedClaims({
            "gty": "client-credentials",
            "sub": "client",
        })
        
        # Should not raise
        rule.validate(claims)

    def test_fails_when_grant_type_differs(self):
        """Test validation fails when grant type is different."""
        rule = RequireGrantType("client-credentials")
        claims = TrustedClaims({
            "gty": "authorization_code",
            "sub": "user",
        })
        
        with pytest.raises(InvalidClaimError) as exc_info:
            rule.validate(claims)
        
        assert "client-credentials" in str(exc_info.value)
        assert "authorization_code" in str(exc_info.value)

    def test_fails_when_grant_type_missing(self):
        """Test validation fails when gty claim is missing."""
        rule = RequireGrantType("client-credentials")
        claims = TrustedClaims({"sub": "user"})
        
        with pytest.raises(InvalidClaimError):
            rule.validate(claims)


class TestRequireClaim:
    """Tests for RequireClaim rule."""

    def test_passes_when_claim_present_no_value_check(self):
        """Test validation passes when claim is present (no value check)."""
        rule = RequireClaim("custom_claim")
        claims = TrustedClaims({
            "custom_claim": "any_value",
            "sub": "user",
        })
        
        # Should not raise
        rule.validate(claims)

    def test_fails_when_claim_missing(self):
        """Test validation fails when required claim is missing."""
        rule = RequireClaim("custom_claim")
        claims = TrustedClaims({"sub": "user"})
        
        with pytest.raises(InvalidClaimError) as exc_info:
            rule.validate(claims)
        
        assert "custom_claim" in str(exc_info.value)
        assert "missing" in str(exc_info.value).lower()

    def test_passes_when_claim_matches_expected_value(self):
        """Test validation passes when claim matches expected value."""
        rule = RequireClaim("role", expected_value="admin")
        claims = TrustedClaims({
            "role": "admin",
            "sub": "user",
        })
        
        # Should not raise
        rule.validate(claims)

    def test_fails_when_claim_value_differs(self):
        """Test validation fails when claim value differs from expected."""
        rule = RequireClaim("role", expected_value="admin")
        claims = TrustedClaims({
            "role": "user",
            "sub": "user",
        })
        
        with pytest.raises(InvalidClaimError) as exc_info:
            rule.validate(claims)
        
        assert "admin" in str(exc_info.value)
        assert "user" in str(exc_info.value)


class TestRequireSubject:
    """Tests for RequireSubject rule."""

    def test_passes_when_subject_matches(self):
        """Test validation passes when subject matches."""
        rule = RequireSubject("user123")
        claims = TrustedClaims({"sub": "user123"})
        
        # Should not raise
        rule.validate(claims)

    def test_fails_when_subject_differs(self):
        """Test validation fails when subject is different."""
        rule = RequireSubject("user123")
        claims = TrustedClaims({"sub": "user456"})
        
        with pytest.raises(InvalidClaimError) as exc_info:
            rule.validate(claims)
        
        assert "user123" in str(exc_info.value)
        assert "user456" in str(exc_info.value)

    def test_fails_when_subject_missing(self):
        """Test validation fails when sub claim is missing."""
        rule = RequireSubject("user123")
        claims = TrustedClaims({"iss": "issuer"})
        
        with pytest.raises(InvalidClaimError):
            rule.validate(claims)
