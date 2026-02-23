"""
Base claims module.

Provides the TrustedClaims class that wraps verified JWT claims.
"""

from typing import Any, Iterator, Mapping


class TrustedClaims(Mapping[str, Any]):
    """Immutable container for verified JWT claims.

    Example:
        claims = TrustedClaims({"sub": "user-123", "scope": "read:users"})
        if claims.subject == "user-123":
            ...

    This object is created ONLY after the token signature has been verified.
    It provides read-only access to claims through a dict-like interface.
    """

    def __init__(
        self,
        claims: dict[str, Any],
        headers: dict[str, Any] | None = None,
    ) -> None:
        """
        Initialize TrustedClaims with verified claim data.

        Args:
            claims: Dictionary of verified JWT claims.
            headers: Optional dictionary containing the JWT header values.
        """
        # Create shallow copies so downstream code cannot mutate shared data.
        self._claims: dict[str, Any] = claims.copy()
        self._headers: dict[str, Any] = headers.copy() if headers else {}

    def __getitem__(self, key: str) -> Any:
        """Get a claim value by key."""
        return self._claims[key]

    def __iter__(self) -> Iterator[str]:
        """Iterate over claim keys."""
        return iter(self._claims)

    def __len__(self) -> int:
        """Return the number of claims."""
        return len(self._claims)

    def __repr__(self) -> str:
        """Return a string representation of the claims."""
        return f"TrustedClaims({self._claims})"

    @property
    def headers(self) -> dict[str, Any]:
        """Return a copy of the JWT headers associated with the claims."""
        return self._headers.copy()

    def get_header(self, key: str, default: Any = None) -> Any:
        """Retrieve a header value with an optional default."""
        return self._headers.get(key, default)

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a claim value with an optional default.

        Args:
            key: The claim name to retrieve.
            default: Value to return if the claim is not present.

        Returns:
            The claim value or the default.
        """
        return self._claims.get(key, default)

    @property
    def subject(self) -> str | None:
        """Return the 'sub' (subject) claim."""
        return self.get("sub")

    @property
    def issuer(self) -> str | None:
        """Return the 'iss' (issuer) claim."""
        return self.get("iss")

    @property
    def audience(self) -> str | list[str] | None:
        """Return the 'aud' (audience) claim."""
        return self.get("aud")

    @property
    def expiration(self) -> int | None:
        """Return the 'exp' (expiration) claim as a Unix timestamp."""
        return self.get("exp")

    @property
    def issued_at(self) -> int | None:
        """Return the 'iat' (issued at) claim as a Unix timestamp."""
        return self.get("iat")

    @property
    def not_before(self) -> int | None:
        """Return the 'nbf' (not before) claim as a Unix timestamp."""
        return self.get("nbf")

    @property
    def jwt_id(self) -> str | None:
        """Return the 'jti' (JWT ID) claim."""
        return self.get("jti")

    def to_dict(self) -> dict[str, Any]:
        """
        Return a copy of the claims as a dictionary.

        Returns:
            A dictionary containing all claims.
        """
        return self._claims.copy()
