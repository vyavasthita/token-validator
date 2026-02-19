"""
JWT Library Demo.

This script demonstrates the jwt_lib architecture for validating JWT tokens.
It showcases:
1. Separation of concerns: JWTVerifier (crypto) vs TokenProfile (business logic)
2. Predefined profiles for User and Auth0 tokens
3. Optional scope validation using RequireScopes
4. Error handling

Architecture:
    Token → JWTVerifier (signature, exp, iss, aud) → TrustedClaims → TokenProfile (business rules)
"""

import asyncio
import os

from jwt_lib.src.authenticator import (
    Auth0Authenticator,
    UserAuthenticator,
)
from jwt_lib.src.validation import RequireScopes
from jwt_lib.src.exceptions import (
    AlgorithmNotAllowedError,
    ExpiredTokenError,
    InvalidAudienceError,
    InvalidClaimError,
    InvalidIssuerError,
    InvalidTokenError,
    MissingClaimError,
    PermissionDeniedError,
    SigningKeyNotFoundError,
    TokenNotYetValidError,
)

# =============================================================================
# Constants
# =============================================================================

# =============================================================================
# Demo Functions
# =============================================================================

async def demo_architecture_summary() -> None:
    """Demo: Architecture summary and best practices."""
    print("\n" + "=" * 70)
    print("ARCHITECTURE SUMMARY")
    print("=" * 70)

    print("""
┌─────────────────────────────────────────────────────────────────────┐
│                        RECOMMENDED DESIGN                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│    JWT Token                                                        │
│        │                                                            │
│        ▼                                                            │
│  ┌───────────────────────────────────────────────────────┐          │
│  │  JWTVerifier (Single Responsibility: Cryptography)    │          │
│  │  • Signature verification via JWKS                    │          │
│  │  • Standard claims: exp, nbf, iat, iss, aud           │          │
│  └───────────────────────────────────────────────────────┘          │
│        │                                                            │
│        ▼ TrustedClaims                                              │
│  ┌───────────────────────────────────────────────────────┐          │
│  │  TokenProfile (Strategy Pattern: Business Logic)      │          │
│  │  • UserTokenProfile                                   │          │
│  │  • Auth0Profile                                       │          │
│  └───────────────────────────────────────────────────────┘          │
│                                                                     │
├─────────────────────────────────────────────────────────────────────┤
│  WHY THIS DESIGN?                                                   │
│                                                                     │
│  ✓ SRP: Verifier handles crypto, Profile handles business rules     │
│  ✓ Open/Closed: Add new profiles without modifying verifier         │
│  ✓ Encapsulation: Domain knowledge in profiles, not client code     │
│  ✓ Testability: Each component can be tested independently          │
│                                                                     │
├─────────────────────────────────────────────────────────────────────┤
│  USAGE IN PRODUCTION:                                               │
│                                                                     │
│  # Configure once at startup                                        │
│  verifier = JWTVerifier(issuer="...", audience="...")               |
│  user_profile = UserTokenProfile(...)                               │
│                                                                     │
│  # In auth middleware                                               │
│  async def authenticate(token: str):                                │
│      claims = await verifier.validate(token)  # Crypto              │
│      user_profile.validate(claims)            # Business rules      │
│      return claims                                                  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
""")

async def demo_user_token() -> None:
    """Demo: Validating live User Tokens."""
    print("\n" + "=" * 70)
    print("DEMO 1: User Token Validation (Real Token)")
    print("=" * 70)

    token = os.getenv("AUTH_TOKEN")

    if not token:
        print(
            "Skipping demo: set AUTH_TOKEN env var with a real user token to run this example."
        )
        return

    try:
        authenticator = UserAuthenticator()

        claims = await authenticator.validate(token)
        print("\n✓ Step 1: Signature + standard claims validated via JWTVerifier")
        print(f"✓ Step 2: Profile validated ({authenticator.profile.profile_name})")
    except (
        AlgorithmNotAllowedError,
        ExpiredTokenError,
        InvalidAudienceError,
        InvalidIssuerError,
        InvalidTokenError,
        SigningKeyNotFoundError,
        TokenNotYetValidError,
        InvalidClaimError,
        MissingClaimError,
        PermissionDeniedError,
    ) as error:
        print(str(error))
    except Exception as error:
        print(f"✗ Unexpected error: {error}")

async def demo_auth0_token_validation() -> None:
    """Demo: Validating a real Auth0 token supplied via environment variable."""
    print("\n" + "=" * 70)
    print("DEMO 3: Auth0 Client Code Using Real Token")
    print("=" * 70)

    token = os.getenv("AUTH_0_TOKEN")

    if not token:
        print(
            f"Skipping demo: set AUTH_0_TOKEN env var with a real token to run this example."
        )
        return

    scope_rules = RequireScopes(["update:core"])

    issuer = ""
    audience = ""

    try:
        authenticator = Auth0Authenticator(
            issuer=issuer,
            audience=audience,
            profile_kwargs={"app_name": "lmr-db-client"}
        )

        claims = await authenticator.validate(token, extra_rules=[scope_rules])
        print("\n✓ Signature + standard claims validated via JWTVerifier")
        print("✓ Auth0 profile validation passed (grant type, appName, azp, optional scopes)")
    except (
        AlgorithmNotAllowedError,
        ExpiredTokenError,
        InvalidAudienceError,
        InvalidIssuerError,
        InvalidTokenError,
        SigningKeyNotFoundError,
        TokenNotYetValidError,
        InvalidClaimError,
        MissingClaimError,
        PermissionDeniedError,
    ) as error:
        print(str(error))
    except Exception as error:
        print(f"✗ Unexpected error: {error}")
        
async def main() -> None:
    """Run all demos."""
    print("\n" + "#" * 70)
    print("#  JWT Library Demo - Profile-Based Architecture")
    print("#" * 70)

    # await demo_user_token()
    await demo_auth0_token_validation()
    # await demo_architecture_summary()

    print("\n" + "=" * 70)
    print("Demo complete!")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    asyncio.run(main())