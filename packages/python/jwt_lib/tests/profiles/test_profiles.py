"""Tests for token profiles module."""

import time
import pytest

from jwt_lib.src.claims import TrustedClaims
from jwt_lib.src.profiles import (
    UserProfile,
    Auth0Profile,
)
from jwt_lib.src.exceptions import InvalidClaimError, PermissionDeniedError
from jwt_lib.src.validation.rules import RequireScopes

USER_ISSUER = "https://auth.example.test/"
USER_AUDIENCE = "https://api.example.test"
USER_TOKEN_TYPE = "UserAuthToken"


# ============================================================================
# Test UserProfile
# ============================================================================


class TestUserProfile:
    """Tests for user token profile."""

    @staticmethod
    def _claims_with(
        base_claims: TrustedClaims,
        header_overrides: dict | None = None,
        **claim_overrides,
    ) -> TrustedClaims:
        """Utility to clone claims with overrides (including headers)."""
        claims_payload = {**base_claims.to_dict(), **claim_overrides}
        headers = base_claims.headers

        if header_overrides:
            for key, value in header_overrides.items():
                if value is None:
                    headers.pop(key, None)
                else:
                    headers[key] = value

        return TrustedClaims(claims_payload, headers=headers)

    @pytest.fixture
    def token_headers(self) -> dict[str, str]:
        """Default JWT headers for user tokens."""
        return {"kid": "test-key", "typ": "JWT", "alg": "RS256"}

    @pytest.fixture
    def valid_user_claims(self, token_headers: dict[str, str]) -> TrustedClaims:
        """Create valid user token claims."""
        now = int(time.time())
        return TrustedClaims({
            "iss": USER_ISSUER,
            "sub": "user@example.com",
            "aud": USER_AUDIENCE,
            "exp": now + 3600,
            "iat": now - 60,
            "nbf": now - 60,
            "tokenType": USER_TOKEN_TYPE,
            "connectionMethod": "UIDPWD",
            "principalType": "USER",
        }, headers=token_headers)

    @pytest.fixture
    def profile(self) -> UserProfile:
        """Create default user profile."""
        return UserProfile(issuer=USER_ISSUER, audience=USER_AUDIENCE)

    def test_valid_claims_pass(self, profile, valid_user_claims):
        """Test that valid claims pass validation."""
        profile.validate(valid_user_claims)  # Should not raise

    def test_wrong_token_type_fails(self, profile, valid_user_claims):
        """Test that wrong tokenType fails."""
        claims = self._claims_with(
            valid_user_claims,
            tokenType="WrongType",
        )
        with pytest.raises(InvalidClaimError, match="tokenType"):
            profile.validate(claims)

    def test_wrong_principal_type_fails(self, profile, valid_user_claims):
        """Test that wrong principalType fails."""
        claims = self._claims_with(
            valid_user_claims,
            principalType="SERVICE",
        )
        with pytest.raises(InvalidClaimError, match="principalType"):
            profile.validate(claims)

    def test_invalid_connection_method_fails(self, profile, valid_user_claims):
        """Test that invalid connectionMethod fails."""
        claims = self._claims_with(
            valid_user_claims,
            connectionMethod="INVALID",
        )
        with pytest.raises(InvalidClaimError, match="connectionMethod"):
            profile.validate(claims)

    def test_invalid_audience_fails(self, profile, valid_user_claims):
        """aud must match the configured audience when provided."""
        claims = self._claims_with(
            valid_user_claims,
            aud="https://api.other.example",
        )

        with pytest.raises(InvalidClaimError, match="aud"):
            profile.validate(claims)

    def test_profile_name(self, profile):
        """Test profile name property."""
        assert profile.profile_name == "UserToken"

    def test_invalid_issuer_fails(self, profile, valid_user_claims):
        """iss must match the configured issuer."""
        claims = self._claims_with(
            valid_user_claims,
            iss="https://other-issuer.example.com",
        )

        with pytest.raises(InvalidClaimError, match="iss"):
            profile.validate(claims)


# ============================================================================
# Test Auth0Profile
# ============================================================================


class TestAuth0Profile:
    """Tests for Auth0Profile."""

    def test_profile_validates_claims(self):
        """Profile should validate matching Auth0 claims."""
        claims = TrustedClaims({
            "iss": "https://auth.example.test/",
            "aud": "https://api.example.test",
            "sub": "client@clients",
            "exp": 9999999999,
            "scope": "read:models write:models",
            "gty": "client-credentials",
            "azp": "svc-client",
            "appName": "svc-app",
        })

        profile = Auth0Profile(
            issuer="https://auth.example.test/",
            audience="https://api.example.test",
            app_name="svc-app",
        )

        profile.validate(claims)

    def test_profile_rejects_missing_scope(self):
        """Missing required scope should raise PermissionDeniedError."""
        claims = TrustedClaims({
            "iss": "https://auth.example.test/",
            "aud": "https://api.example.test",
            "sub": "client@clients",
            "exp": 9999999999,
            "scope": "read:models",
            "gty": "client-credentials",
            "azp": "svc-client",
            "appName": "svc-app",
        })

        profile = Auth0Profile(
            issuer="https://auth.example.test/",
            audience="https://api.example.test",
            app_name="svc-app",
        )

        with pytest.raises(PermissionDeniedError):
            profile.validate(
                claims,
                extra_rules=[RequireScopes(["write:models"])],
            )

    def test_profile_rejects_wrong_app_name(self):
        """Mismatched appName should raise InvalidClaimError."""
        claims = TrustedClaims({
            "iss": "https://auth.example.test/",
            "aud": "https://api.example.test",
            "sub": "client@clients",
            "exp": 9999999999,
            "scope": "read:models",
            "gty": "client-credentials",
            "azp": "svc-client",
            "appName": "other-app",
        })

        profile = Auth0Profile(
            issuer="https://auth.example.test/",
            audience="https://api.example.test",
            app_name="svc-app",
        )

        with pytest.raises(InvalidClaimError, match="appName"):
            profile.validate(claims)

    def test_profile_rejects_wrong_grant_type(self):
        """Non client-credentials grant should fail validation."""
        claims = TrustedClaims({
            "iss": "https://auth.example.test/",
            "aud": "https://api.example.test",
            "sub": "client@clients",
            "exp": 9999999999,
            "scope": "read:models",
            "gty": "password",
            "azp": "svc-client",
            "appName": "svc-app",
        })

        profile = Auth0Profile(
            issuer="https://auth.example.test/",
            audience="https://api.example.test",
            app_name="svc-app",
        )

        with pytest.raises(InvalidClaimError, match="gty"):
            profile.validate(claims)

