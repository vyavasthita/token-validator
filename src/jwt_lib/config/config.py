"""Shared default configuration values for built-in token profiles."""

from typing import Final

JWKS_FETCH_TIMEOUT_SECONDS: int = 1
REQUIRED_CLAIMS: tuple[str, ...] = ("exp", "iss", "sub")

# Default JWKS cache TTL in seconds. The consuming service can override this
# by passing cache_ttl to the authenticator/verifier constructors.
JWKS_CACHE_TTL_SECONDS: float = 300.0

# Auth0 Token Configuration
AUTH_0_ALLOWED_ALGORITHMS = ("RS256",)
AUTH_0_GRANT_TYPE = "client-credentials"

# User Token Configuration
USER_ALLOWED_ALGORITHMS = ("RS256",)
USER_TOKEN_TYPE = "AuthToken"
USER_PRINCIPAL_TYPE = "USER"
USER_MAX_TOKEN_AGE_SECONDS: Final[int | None] = None

USER_ALLOWED_CONNECTION_METHODS: Final[tuple[str, ...]] = (
    "SAML",
    "UIDPWD",
)

USER_CLOCK_SKEW_SECONDS = 60
USER_HEADER_TYP = "JWT"
USER_HEADER_ALG = "RS256"
USER_PROFILE_NAME = "UserToken"
