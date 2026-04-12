"""
JWT Library Exceptions.

This module defines all custom exceptions raised by the JWT validation library.
Each exception includes a descriptive default message that can be overridden.
"""


class JWTError(Exception):
    """Base class for all JWT verification errors."""

    default_message = "An error occurred during JWT processing."

    def __init__(self, message: str | None = None):
        super().__init__(message or self.default_message)


class InvalidTokenError(JWTError):
    """Raised when the token is malformed, has an invalid signature, or uses an unsupported algorithm."""

    default_message = "The token is invalid: malformed, bad signature, or unsupported algorithm."


class ExpiredTokenError(JWTError):
    """Raised when the token has expired (exp claim is in the past)."""

    default_message = "The token has expired."


class TokenNotYetValidError(JWTError):
    """Raised when the token is not yet valid (nbf claim is in the future)."""

    default_message = "The token is not yet valid (nbf claim is in the future)."


class InvalidIssuerError(JWTError):
    """Raised when the token issuer does not match the expected issuer."""

    default_message = "The token issuer is invalid or does not match the expected issuer."


class InvalidAudienceError(JWTError):
    """Raised when the token audience does not match the expected audience."""

    default_message = "The token audience is invalid or does not match the expected audience."


class MissingClaimError(JWTError):
    """Raised when a required claim is missing from the token."""

    default_message = "A required claim is missing from the token."


class InvalidClaimError(JWTError):
    """Raised when a claim value fails validation."""

    default_message = "A claim value is invalid."


class PermissionDeniedError(JWTError):
    """Raised when the token lacks required scopes or permissions."""

    default_message = "Permission denied: the token lacks required scopes or permissions."


class AlgorithmNotAllowedError(JWTError):
    """Raised when the token uses an algorithm not in the allowed list."""

    default_message = "The token algorithm is not allowed."


class SigningKeyNotFoundError(JWTError):
    """Raised when the signing key cannot be found in JWKS."""

    default_message = "The signing key was not found in JWKS."


class ConfigurationError(JWTError):
    """Raised when required configuration (issuer, jwks_host, etc.) is missing or invalid."""

    default_message = "Required JWT configuration is missing or invalid."