"""
Access Token Claims module.

Specialized wrapper for OAuth2 access token claims with convenient accessors.
"""

from typing import Any

from .trusted_claims import TrustedClaims


class AccessTokenClaims(TrustedClaims):
    """
    Specialized wrapper for OAuth2 Access Token claims.

    Provides convenient property accessors for common OAuth2/OIDC claims
    like 'scope', 'azp' (authorized party), and 'gty' (grant type).

    Example:
        claims = AccessTokenClaims(verified_claims)
        if claims.has_scopes(["read:users", "write:users"]):
            # proceed with operation
    """

    def __init__(self, claims: dict[str, Any]) -> None:
        """
        Initialize AccessTokenClaims with verified claim data.

        Args:
            claims: Dictionary of verified JWT claims.
        """
        super().__init__(claims)

    @property
    def scopes(self) -> list[str]:
        """
        Return the list of scopes from the 'scope' claim.

        The 'scope' claim is expected to be a space-separated string.

        Returns:
            List of scope strings. Empty list if no scope claim present.
        """
        scope_str: str | None = self.get("scope")

        if not scope_str:
            return []
        
        return scope_str.split()

    @property
    def authorized_party(self) -> str | None:
        """
        Return the 'azp' (authorized party) claim.

        The azp claim identifies the party to which the token was issued.

        Returns:
            The authorized party identifier or None if not present.
        """
        return self.get("azp")

    @property
    def client_id(self) -> str | None:
        """
        Return the client ID from the token.

        Tries 'client_id' first, then falls back to 'azp'.

        Returns:
            The client identifier or None if not present.
        """
        return self.get("client_id") or self.get("azp")

    @property
    def grant_type(self) -> str | None:
        """
        Return the 'gty' (grant type) claim.

        Useful to distinguish client-credential tokens from user tokens.

        Returns:
            The grant type string or None if not present.
        """
        return self.get("gty")

    def has_scopes(self, required_scopes: list[str]) -> bool:
        """
        Check if all required scopes are present in this token.

        Args:
            required_scopes: List of scope strings that must be present.

        Returns:
            True if all required scopes are present, False otherwise.
        """
        return set(required_scopes).issubset(set(self.scopes))

    def has_any_scope(self, scopes: list[str]) -> bool:
        """
        Check if any of the specified scopes are present in this token.

        Args:
            scopes: List of scope strings to check for.

        Returns:
            True if at least one scope is present, False otherwise.
        """
        return bool(set(scopes) & set(self.scopes))
