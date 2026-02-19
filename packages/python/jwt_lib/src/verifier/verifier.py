"""
JWT Verifier module.

Provides the main JWTVerifier class for verifying JWT tokens. This layer owns
cryptographic validation (JWKS lookup, signature verification, spec-mandated
claims such as `iss`, `aud`, `exp`, `nbf`) and produces a `TrustedClaims`
instance that downstream profiles can trust. Domain-specific checks stay in
`TokenProfile` subclasses so cryptography code remains minimal and reusable.
"""

import jwt
from typing import Any, Iterable
from jwt import PyJWKClient
from jwt.exceptions import (
    ExpiredSignatureError,
    InvalidAudienceError as PyJWTInvalidAudienceError,
    InvalidIssuerError as PyJWTInvalidIssuerError,
    ImmatureSignatureError,
    InvalidTokenError as PyJWTInvalidTokenError,
)

from jwt_lib.src.claims import TrustedClaims
from jwt_lib.src.exceptions import (
    InvalidTokenError,
    ExpiredTokenError,
    TokenNotYetValidError,
    InvalidIssuerError,
    InvalidAudienceError,
    AlgorithmNotAllowedError,
    SigningKeyNotFoundError,
)


class JWTVerifier:
    """
    JWT token verifier that derives its JWKS endpoint from the issuer.

    This layer owns cryptographic validation: signature verification, header
    algorithm enforcement, and the standard JWT claims (`iss`, `aud`, `exp`,
    `nbf`). The JWKS URI automatically follows the `/.well-known/jwks.json`
    convention, so callers only provide the issuer and any optional overrides.

    Example:
        verifier = JWTVerifier(
            issuer="https://auth.example.com/",
            audience="my-api",
            allowed_algorithms=["RS256"],
        )
        claims = await verifier.validate(token)

    Attributes:
        issuer: Expected token issuer (stored with a trailing slash).
        audience: Expected token audience (optional).
        allowed_algorithms: Set of allowed signing algorithms.
        required_claims: List of claims that must be present.
    """

    # Default claims that must be present in the token
    DEFAULT_REQUIRED_CLAIMS = ["exp", "iss", "sub"]

    def __init__(
        self,
        issuer: str,
        audience: str | None = None,
        allowed_algorithms: Iterable[str] | None = None,
        required_claims: list[str] | None = None,
    ) -> None:
        """
        Initialize the JWT verifier.

        Args:
            issuer: The expected issuer of the token (iss claim).
            audience: The expected audience (aud claim). Optional.
            allowed_algorithms: Allowed signing algorithms. Defaults to ["RS256"].
            required_claims: Claims that must be present. Defaults to ["exp", "iss", "sub"].
        """
        self.issuer = issuer.rstrip("/") + "/"  # Normalize to single trailing slash
        self.audience = audience
        self.allowed_algorithms = set(allowed_algorithms or ["RS256"])
        self.required_claims = required_claims or self.DEFAULT_REQUIRED_CLAIMS.copy()

        # Add 'aud' to required claims if audience is specified
        if audience and "aud" not in self.required_claims:
            self.required_claims.append("aud")

        self._jwks_client = PyJWKClient(self.jwks_uri)

    def _get_unverified_header(self, token: str) -> dict[str, Any]:
        """
        Extract the unverified header from a JWT token.

        Args:
            token: The JWT token string.

        Returns:
            Dictionary containing the token header.

        Raises:
            InvalidTokenError: If the token format is invalid.
        """
        try:
            return jwt.get_unverified_header(token)
        except PyJWTInvalidTokenError as exc:
            raise InvalidTokenError("Invalid token format") from exc

    def _validate_algorithm(self, header: dict[str, Any]) -> None:
        """
        Validate that the token uses an allowed algorithm.

        Args:
            header: The token header dictionary.

        Raises:
            AlgorithmNotAllowedError: If the algorithm is not allowed.
        """
        algorithm = header.get("alg")
        
        if algorithm not in self.allowed_algorithms:
            raise AlgorithmNotAllowedError(
                f"Algorithm '{algorithm}' is not allowed. "
                f"Allowed: {', '.join(sorted(self.allowed_algorithms))}"
            )

    def _get_signing_key(self, token: str, jwks_client: PyJWKClient) -> Any:
        """
        Get the signing key for the token from JWKS.

        Args:
            token: The JWT token string.
            jwks_client: The PyJWKClient to use.

        Returns:
            The signing key.

        Raises:
            SigningKeyNotFoundError: If the key cannot be found.
        """
        try:
            signing_key = jwks_client.get_signing_key_from_jwt(token)
            return signing_key.key
        except Exception as exc:
            raise SigningKeyNotFoundError(
                "Could not find signing key for token"
            ) from exc

    def _decode_and_verify(self, token: str, key: Any) -> dict[str, Any]:
        """
        Decode and verify the JWT token.

        Args:
            token: The JWT token string.
            key: The signing key for verification.

        Returns:
            Dictionary of verified claims.

        Raises:
            ExpiredTokenError: If the token has expired.
            TokenNotYetValidError: If the token is not yet valid.
            InvalidIssuerError: If the issuer does not match.
            InvalidAudienceError: If the audience does not match.
            InvalidTokenError: For other validation failures.
        """
        options = {
            "require": self.required_claims,
            "verify_exp": True,
            "verify_nbf": True,
            "verify_iss": True,
            "verify_aud": self.audience is not None,
        }

        issuers: set[str] = {self.issuer}
        issuer_without_slash = self.issuer.rstrip("/")

        if issuer_without_slash:
            issuers.add(issuer_without_slash)

        try:
            claims = jwt.decode(
                token,
                key,
                algorithms=list(self.allowed_algorithms),
                audience=self.audience,
                issuer=tuple(issuers),
                options=options,
            )
            return claims

        except ExpiredSignatureError as exc:
            raise ExpiredTokenError("The token has expired") from exc

        except ImmatureSignatureError as exc:
            raise TokenNotYetValidError(
                "The token is not yet valid (nbf claim is in the future)"
            ) from exc

        except PyJWTInvalidIssuerError as exc:
            raise InvalidIssuerError(
                f"Token issuer does not match expected issuer '{self.issuer}'"
            ) from exc

        except PyJWTInvalidAudienceError as exc:
            raise InvalidAudienceError(
                f"Token audience does not match expected audience '{self.audience}'"
            ) from exc

        except PyJWTInvalidTokenError as exc:
            raise InvalidTokenError(f"Token validation failed: {exc}") from exc

    async def validate(self, token: str) -> TrustedClaims:
        """
        Verify a JWT token and return the validated claims.

        This method performs:
        1. Header validation (algorithm check)
        2. Signature verification using JWKS
        3. Standard claim validation (exp, nbf, iss, aud)

        Args:
            token: The JWT token string to verify.

        Returns:
            TrustedClaims containing the verified token claims.

        Raises:
            AlgorithmNotAllowedError: If the token uses a disallowed algorithm.
            ExpiredTokenError: If the token has expired.
            TokenNotYetValidError: If the token is not yet valid (nbf).
            InvalidIssuerError: If the issuer does not match.
            InvalidAudienceError: If the audience does not match.
            SigningKeyNotFoundError: If the signing key cannot be found.
            InvalidTokenError: For other token validation failures.
        """
        # Validate header and get algorithm
        header = self._get_unverified_header(token)
        
        self._validate_algorithm(header)

        # Get signing key from JWKS
        key = self._get_signing_key(token, self._jwks_client)

        # Decode and verify the token
        claims = self._decode_and_verify(token, key)

        return TrustedClaims(claims, headers=header)

    @property
    def jwks_uri(self) -> str:
        """Return the JWKS endpoint derived from the issuer."""
        return f"{self.issuer.rstrip('/')}/.well-known/jwks.json"


