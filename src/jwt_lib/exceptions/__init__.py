"""Exceptions module for JWT library."""

from .errors import (
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
    ConfigurationError,
)

__all__ = [
    "JWTError",
    "InvalidTokenError",
    "ExpiredTokenError",
    "TokenNotYetValidError",
    "InvalidIssuerError",
    "InvalidAudienceError",
    "MissingClaimError",
    "InvalidClaimError",
    "PermissionDeniedError",
    "AlgorithmNotAllowedError",
    "SigningKeyNotFoundError",
    "ConfigurationError",
]