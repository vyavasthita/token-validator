"""Claims module for JWT library."""

from .trusted_claims import TrustedClaims
from .access_token_claims import AccessTokenClaims

__all__ = [
    "TrustedClaims",
    "AccessTokenClaims",
]