"""Tests for TrustedClaims class."""

import pytest

from jwt_lib.src.claims import TrustedClaims


class TestTrustedClaims:
    """Tests for the TrustedClaims class."""

    @pytest.fixture
    def sample_claims(self) -> dict:
        """Sample claims for testing."""
        return {
            "iss": "https://auth.example.com/",
            "aud": "test-api",
            "sub": "user123",
            "exp": 1700000000,
            "iat": 1699996400,
            "nbf": 1699996400,
            "jti": "unique-token-id",
            "custom_claim": "custom_value",
        }

    def test_initialization(self, sample_claims: dict):
        """Test that TrustedClaims initializes correctly."""
        claims = TrustedClaims(sample_claims)
        assert claims is not None

    def test_immutability(self, sample_claims: dict):
        """Test that modifying the original dict does not affect TrustedClaims."""
        claims = TrustedClaims(sample_claims)
        original_iss = claims["iss"]
        
        # Modify original dict
        sample_claims["iss"] = "modified"
        
        # TrustedClaims should be unchanged
        assert claims["iss"] == original_iss

    def test_getitem(self, sample_claims: dict):
        """Test __getitem__ access."""
        claims = TrustedClaims(sample_claims)
        assert claims["sub"] == "user123"
        assert claims["iss"] == "https://auth.example.com/"

    def test_getitem_missing_key_raises(self, sample_claims: dict):
        """Test that accessing missing key raises KeyError."""
        claims = TrustedClaims(sample_claims)
        with pytest.raises(KeyError):
            _ = claims["nonexistent"]

    def test_get_with_default(self, sample_claims: dict):
        """Test get method with default value."""
        claims = TrustedClaims(sample_claims)
        assert claims.get("nonexistent") is None
        assert claims.get("nonexistent", "default") == "default"
        assert claims.get("sub") == "user123"

    def test_iter(self, sample_claims: dict):
        """Test iteration over claim keys."""
        claims = TrustedClaims(sample_claims)
        keys = list(claims)
        assert set(keys) == set(sample_claims.keys())

    def test_len(self, sample_claims: dict):
        """Test length of claims."""
        claims = TrustedClaims(sample_claims)
        assert len(claims) == len(sample_claims)

    def test_contains(self, sample_claims: dict):
        """Test 'in' operator."""
        claims = TrustedClaims(sample_claims)
        assert "sub" in claims
        assert "nonexistent" not in claims

    def test_repr(self, sample_claims: dict):
        """Test string representation."""
        claims = TrustedClaims(sample_claims)
        repr_str = repr(claims)
        assert "TrustedClaims" in repr_str
        assert "user123" in repr_str

    def test_to_dict(self, sample_claims: dict):
        """Test to_dict returns a copy."""
        claims = TrustedClaims(sample_claims)
        claims_dict = claims.to_dict()
        
        # Should equal original
        assert claims_dict == sample_claims
        
        # Should be a copy
        claims_dict["modified"] = True
        assert "modified" not in claims

    def test_headers_property_returns_copy(self, sample_claims: dict):
        """Headers property should return a defensive copy."""
        claims = TrustedClaims(sample_claims, headers={"kid": "abc"})
        headers = claims.headers
        headers["kid"] = "mutated"

        assert claims.get_header("kid") == "abc"

    def test_get_header_with_default(self, sample_claims: dict):
        """get_header should honor defaults."""
        claims = TrustedClaims(sample_claims, headers={"kid": "abc"})

        assert claims.get_header("kid") == "abc"
        assert claims.get_header("missing", "default") == "default"


class TestTrustedClaimsProperties:
    """Tests for TrustedClaims property accessors."""

    @pytest.fixture
    def sample_claims(self) -> dict:
        """Sample claims for testing."""
        return {
            "iss": "https://auth.example.com/",
            "aud": "test-api",
            "sub": "user123",
            "exp": 1700000000,
            "iat": 1699996400,
            "nbf": 1699996400,
            "jti": "unique-token-id",
        }

    def test_subject_property(self, sample_claims: dict):
        """Test subject property."""
        claims = TrustedClaims(sample_claims)
        assert claims.subject == "user123"

    def test_issuer_property(self, sample_claims: dict):
        """Test issuer property."""
        claims = TrustedClaims(sample_claims)
        assert claims.issuer == "https://auth.example.com/"

    def test_audience_property(self, sample_claims: dict):
        """Test audience property."""
        claims = TrustedClaims(sample_claims)
        assert claims.audience == "test-api"

    def test_audience_as_list(self):
        """Test audience property with list value."""
        claims = TrustedClaims({
            "aud": ["api1", "api2"],
            "sub": "user",
            "iss": "issuer",
            "exp": 1700000000,
        })
        assert claims.audience == ["api1", "api2"]

    def test_expiration_property(self, sample_claims: dict):
        """Test expiration property."""
        claims = TrustedClaims(sample_claims)
        assert claims.expiration == 1700000000

    def test_issued_at_property(self, sample_claims: dict):
        """Test issued_at property."""
        claims = TrustedClaims(sample_claims)
        assert claims.issued_at == 1699996400

    def test_not_before_property(self, sample_claims: dict):
        """Test not_before property."""
        claims = TrustedClaims(sample_claims)
        assert claims.not_before == 1699996400

    def test_jwt_id_property(self, sample_claims: dict):
        """Test jwt_id property."""
        claims = TrustedClaims(sample_claims)
        assert claims.jwt_id == "unique-token-id"

    def test_missing_optional_properties(self):
        """Test that missing optional properties return None."""
        claims = TrustedClaims({"sub": "user", "exp": 1700000000})
        assert claims.issuer is None
        assert claims.audience is None
        assert claims.not_before is None
        assert claims.issued_at is None
        assert claims.jwt_id is None
