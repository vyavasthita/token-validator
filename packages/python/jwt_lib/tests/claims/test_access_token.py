"""Tests for AccessTokenClaims class."""

import pytest

from jwt_lib.src.claims import AccessTokenClaims


class TestAccessTokenClaims:
    """Tests for the AccessTokenClaims class."""

    @pytest.fixture
    def sample_claims(self) -> dict:
        """Sample OAuth2 access token claims."""
        return {
            "iss": "https://auth.example.com/",
            "aud": "test-api",
            "sub": "user123",
            "exp": 1700000000,
            "iat": 1699996400,
            "scope": "read:users write:users admin",
            "azp": "client-app-id",
            "gty": "client-credentials",
            "client_id": "my-client-id",
        }

    def test_initialization(self, sample_claims: dict):
        """Test that AccessTokenClaims initializes correctly."""
        claims = AccessTokenClaims(sample_claims)
        assert claims is not None

    def test_inherits_trusted_claims(self, sample_claims: dict):
        """Test that AccessTokenClaims inherits from TrustedClaims."""
        from jwt_lib.src.claims import TrustedClaims
        
        claims = AccessTokenClaims(sample_claims)
        assert isinstance(claims, TrustedClaims)


class TestAccessTokenClaimsScopes:
    """Tests for scope-related functionality."""

    def test_scopes_property_parses_space_separated(self):
        """Test that scopes property parses space-separated scope string."""
        claims = AccessTokenClaims({
            "scope": "read:users write:users admin",
            "sub": "user",
            "exp": 1700000000,
        })
        assert claims.scopes == ["read:users", "write:users", "admin"]

    def test_scopes_property_empty_when_missing(self):
        """Test that scopes returns empty list when scope claim is missing."""
        claims = AccessTokenClaims({
            "sub": "user",
            "exp": 1700000000,
        })
        assert claims.scopes == []

    def test_scopes_property_empty_string(self):
        """Test that scopes returns empty list for empty scope string."""
        claims = AccessTokenClaims({
            "scope": "",
            "sub": "user",
            "exp": 1700000000,
        })
        assert claims.scopes == []

    def test_scopes_property_single_scope(self):
        """Test that scopes handles single scope correctly."""
        claims = AccessTokenClaims({
            "scope": "read:users",
            "sub": "user",
            "exp": 1700000000,
        })
        assert claims.scopes == ["read:users"]

    def test_has_scopes_all_present(self):
        """Test has_scopes returns True when all required scopes present."""
        claims = AccessTokenClaims({
            "scope": "read:users write:users admin",
            "sub": "user",
            "exp": 1700000000,
        })
        assert claims.has_scopes(["read:users", "write:users"]) is True

    def test_has_scopes_some_missing(self):
        """Test has_scopes returns False when some scopes missing."""
        claims = AccessTokenClaims({
            "scope": "read:users",
            "sub": "user",
            "exp": 1700000000,
        })
        assert claims.has_scopes(["read:users", "write:users"]) is False

    def test_has_scopes_empty_required(self):
        """Test has_scopes returns True for empty required list."""
        claims = AccessTokenClaims({
            "scope": "read:users",
            "sub": "user",
            "exp": 1700000000,
        })
        assert claims.has_scopes([]) is True

    def test_has_any_scope_at_least_one_present(self):
        """Test has_any_scope returns True when at least one scope present."""
        claims = AccessTokenClaims({
            "scope": "read:users",
            "sub": "user",
            "exp": 1700000000,
        })
        assert claims.has_any_scope(["read:users", "write:users"]) is True

    def test_has_any_scope_none_present(self):
        """Test has_any_scope returns False when no scopes present."""
        claims = AccessTokenClaims({
            "scope": "admin",
            "sub": "user",
            "exp": 1700000000,
        })
        assert claims.has_any_scope(["read:users", "write:users"]) is False

    def test_has_any_scope_empty_list(self):
        """Test has_any_scope returns False for empty list."""
        claims = AccessTokenClaims({
            "scope": "read:users",
            "sub": "user",
            "exp": 1700000000,
        })
        assert claims.has_any_scope([]) is False


class TestAccessTokenClaimsOAuthProperties:
    """Tests for OAuth2-specific properties."""

    def test_authorized_party(self):
        """Test authorized_party property."""
        claims = AccessTokenClaims({
            "azp": "client-app-id",
            "sub": "user",
            "exp": 1700000000,
        })
        assert claims.authorized_party == "client-app-id"

    def test_authorized_party_missing(self):
        """Test authorized_party returns None when missing."""
        claims = AccessTokenClaims({
            "sub": "user",
            "exp": 1700000000,
        })
        assert claims.authorized_party is None

    def test_client_id_property(self):
        """Test client_id property returns client_id claim."""
        claims = AccessTokenClaims({
            "client_id": "my-client",
            "sub": "user",
            "exp": 1700000000,
        })
        assert claims.client_id == "my-client"

    def test_client_id_falls_back_to_azp(self):
        """Test client_id falls back to azp when client_id missing."""
        claims = AccessTokenClaims({
            "azp": "client-from-azp",
            "sub": "user",
            "exp": 1700000000,
        })
        assert claims.client_id == "client-from-azp"

    def test_client_id_prefers_client_id_over_azp(self):
        """Test client_id prefers client_id claim over azp."""
        claims = AccessTokenClaims({
            "client_id": "from-client-id",
            "azp": "from-azp",
            "sub": "user",
            "exp": 1700000000,
        })
        assert claims.client_id == "from-client-id"

    def test_grant_type_property(self):
        """Test grant_type property."""
        claims = AccessTokenClaims({
            "gty": "client-credentials",
            "sub": "user",
            "exp": 1700000000,
        })
        assert claims.grant_type == "client-credentials"

    def test_grant_type_missing(self):
        """Test grant_type returns None when missing."""
        claims = AccessTokenClaims({
            "sub": "user",
            "exp": 1700000000,
        })
        assert claims.grant_type is None
