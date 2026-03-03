"""Tests for JWT library exceptions."""

import pytest

from jwt_lib.exceptions import (
    JWTError,
    InvalidTokenError,
    ExpiredTokenError,
    TokenNotYetValidError,
    InvalidIssuerError,
    InvalidAudienceError,
    MissingClaimError,
    InvalidClaimError,
    PermissionDeniedError,
    AlgorithmNotAllowedError,
    SigningKeyNotFoundError,
)


class TestJWTError:
    """Tests for the base JWTError class."""

    def test_default_message(self):
        """Test that JWTError has a default message."""
        error = JWTError()
        assert str(error) == "An error occurred during JWT processing."

    def test_custom_message(self):
        """Test that JWTError accepts a custom message."""
        error = JWTError("Custom error message")
        assert str(error) == "Custom error message"

    def test_inheritance(self):
        """Test that JWTError inherits from Exception."""
        assert issubclass(JWTError, Exception)


class TestInvalidTokenError:
    """Tests for InvalidTokenError."""

    def test_default_message(self):
        """Test default error message."""
        error = InvalidTokenError()
        assert "invalid" in str(error).lower()

    def test_custom_message(self):
        """Test custom error message."""
        error = InvalidTokenError("Token format is wrong")
        assert str(error) == "Token format is wrong"

    def test_inheritance(self):
        """Test inheritance from JWTError."""
        assert issubclass(InvalidTokenError, JWTError)


class TestExpiredTokenError:
    """Tests for ExpiredTokenError."""

    def test_default_message(self):
        """Test default error message."""
        error = ExpiredTokenError()
        assert "expired" in str(error).lower()

    def test_inheritance(self):
        """Test inheritance from JWTError."""
        assert issubclass(ExpiredTokenError, JWTError)


class TestTokenNotYetValidError:
    """Tests for TokenNotYetValidError."""

    def test_default_message(self):
        """Test default error message."""
        error = TokenNotYetValidError()
        assert "not yet valid" in str(error).lower()

    def test_inheritance(self):
        """Test inheritance from JWTError."""
        assert issubclass(TokenNotYetValidError, JWTError)


class TestInvalidIssuerError:
    """Tests for InvalidIssuerError."""

    def test_default_message(self):
        """Test default error message."""
        error = InvalidIssuerError()
        assert "issuer" in str(error).lower()

    def test_inheritance(self):
        """Test inheritance from JWTError."""
        assert issubclass(InvalidIssuerError, JWTError)


class TestInvalidAudienceError:
    """Tests for InvalidAudienceError."""

    def test_default_message(self):
        """Test default error message."""
        error = InvalidAudienceError()
        assert "audience" in str(error).lower()

    def test_inheritance(self):
        """Test inheritance from JWTError."""
        assert issubclass(InvalidAudienceError, JWTError)


class TestMissingClaimError:
    """Tests for MissingClaimError."""

    def test_default_message(self):
        """Test default error message."""
        error = MissingClaimError()
        assert "missing" in str(error).lower()

    def test_inheritance(self):
        """Test inheritance from JWTError."""
        assert issubclass(MissingClaimError, JWTError)


class TestInvalidClaimError:
    """Tests for InvalidClaimError."""

    def test_default_message(self):
        """Test default error message."""
        error = InvalidClaimError()
        assert "invalid" in str(error).lower()

    def test_inheritance(self):
        """Test inheritance from JWTError."""
        assert issubclass(InvalidClaimError, JWTError)


class TestPermissionDeniedError:
    """Tests for PermissionDeniedError."""

    def test_default_message(self):
        """Test default error message."""
        error = PermissionDeniedError()
        assert "permission" in str(error).lower() or "denied" in str(error).lower()

    def test_inheritance(self):
        """Test inheritance from JWTError."""
        assert issubclass(PermissionDeniedError, JWTError)


class TestAlgorithmNotAllowedError:
    """Tests for AlgorithmNotAllowedError."""

    def test_default_message(self):
        """Test default error message."""
        error = AlgorithmNotAllowedError()
        assert "algorithm" in str(error).lower()

    def test_inheritance(self):
        """Test inheritance from JWTError."""
        assert issubclass(AlgorithmNotAllowedError, JWTError)


class TestSigningKeyNotFoundError:
    """Tests for SigningKeyNotFoundError."""

    def test_default_message(self):
        """Test default error message."""
        error = SigningKeyNotFoundError()
        assert "signing key" in str(error).lower()

    def test_inheritance(self):
        """Test inheritance from JWTError."""
        assert issubclass(SigningKeyNotFoundError, JWTError)


class TestExceptionChaining:
    """Tests for exception chaining behavior."""

    def test_can_be_raised_from_another_exception(self):
        """Test that exceptions can be raised from other exceptions."""
        original = ValueError("Original error")
        
        with pytest.raises(InvalidTokenError) as exc_info:
            try:
                raise original
            except ValueError as e:
                raise InvalidTokenError("Wrapper error") from e
        
        assert exc_info.value.__cause__ is original
