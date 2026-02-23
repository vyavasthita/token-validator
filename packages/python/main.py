"""JWT Library demo runner with simple CLI argument parsing."""

import argparse
import asyncio
import logging
import os

from jwt_lib.src.authenticator import (
    Auth0Authenticator,
    UserAuthenticator,
)
from jwt_lib.src.claims import TrustedClaims
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
# Demo Functions
# =============================================================================

logger = logging.getLogger("jwt_lib.demo")

async def demo_architecture_summary() -> None:
    """Explain how auth0_verifier.py and user_verifier.py fit into the layered pipeline."""
    logger.info("\n%s", "=" * 70)
    logger.info("ARCHITECTURE SUMMARY")
    logger.info("%s", "=" * 70)

    logger.info("""
┌─────────────────────────────────────────────────────────────────────┐
│                        RECOMMENDED DESIGN                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│    JWT Token                                                        │
│        │                                                            │
│        ▼                                                            │
│  ┌───────────────────────────────────────────────────────┐          │
│  │  Auth0/User JWTVerifiers (Single Responsibility)      │          │
│  │  • JWKS signature verification                        │          │
│  │  • Standard claims: exp, nbf, iss, aud                │          │
│  │  • User-only hooks: kid, typ, iat policies            │          │
│  └───────────────────────────────────────────────────────┘          │
│        │                                                            │
│        ▼ TrustedClaims                                              │
│  ┌───────────────────────────────────────────────────────┐          │
│  │  TokenProfile (Strategy Pattern: Business Logic)      │          │
│  │  • UserProfile                                        │          │
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
│  verifier = UserJWTVerifier(issuer="...", jwks_host="...",         │
│                             audience="...")                        │
│  user_profile = UserProfile(...)                                    │
│                                                                     │
│  # In auth middleware                                               │
│  async def authenticate(token: str):                                │
│      claims = await verifier.validate(token)  # Crypto              │
│      user_profile.validate(claims)            # Business rules      │
│      return claims                                                  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
""")

async def demo_auth0_token_validation() -> None:
    """Demo: Validating a real Auth0 token supplied via environment variable."""
    logger.info("\n%s", "=" * 70)
    logger.info("DEMO 3: Auth0 Client Code Using Real Token")
    logger.info("%s", "=" * 70)

    scope_rules: RequireScopes = RequireScopes(["update:core"])

    try:
        authenticator: Auth0Authenticator = Auth0Authenticator(
            issuer=os.getenv("AUTH_0_ISSUER", ""),
            jwks_host=os.getenv("AUTH_0_JWKS_HOST", ""),
            audience=os.getenv("AUTH_0_AUDIENCE"),
            profile_kwargs={"app_name": "lmr-db-client"}
        )

        claims: TrustedClaims = await authenticator.validate(
            os.getenv("AUTH_0_TOKEN", ""),
            extra_rules=[scope_rules],
        )
        logger.info("\n✓ Signature + standard claims validated via Auth0JWTVerifier")
        logger.info("✓ Auth0 profile validation passed (grant type, appName, azp, optional scopes)")
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
        logger.error("%s", error)
    except Exception as error:
        logger.exception("✗ Unexpected error: %s", error)
        
async def demo_user_token() -> None:
    """Demo: Validating live User Tokens."""
    logger.info("\n%s", "=" * 70)
    logger.info("DEMO 1: User Token Validation (Real Token)")
    logger.info("%s", "=" * 70)

    try:
        authenticator: UserAuthenticator = UserAuthenticator(
            issuer=os.getenv("AUTH_USER_ISSUER", ""),
            jwks_host=os.getenv("AUTH_USER_JWKS_HOST", ""),
            audience=os.getenv("AUTH_USER_AUDIENCE"),
        )

        claims: TrustedClaims = await authenticator.validate(os.getenv("AUTH_TOKEN", ""))
        logger.info("\n✓ Step 1: Signature + standard claims validated via UserJWTVerifier")
        logger.info("✓ Step 2: Profile validated (%s)", authenticator.profile.profile_name)
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
        logger.error("%s", error)
    except Exception as error:
        logger.exception("✗ Unexpected error: %s", error)


def build_parser() -> argparse.ArgumentParser:
    """Construct the CLI parser for selecting demos."""
    parser = argparse.ArgumentParser(
        description=(
            "Run one or more JWT library demos. Leave all flags unset to run everything."
        ),
        add_help=False,
    )
    parser.add_argument(
        "-h",
        "--help",
        action="help",
        help="Show this help message and exit.",
    )
    parser.add_argument(
        "--architecture",
        action="store_true",
        help="Run the architecture overview demo.",
    )
    parser.add_argument(
        "--auth0",
        action="store_true",
        help="Run the Auth0 token validation demo.",
    )
    parser.add_argument(
        "--user",
        action="store_true",
        help="Run the first-party user token validation demo.",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run every demo (default when no specific flag is provided).",
    )
    return parser


def selected_demos(args: argparse.Namespace) -> list[str]:
    """Translate CLI flags into the demos that should run."""
    mapping = {
        "architecture": args.architecture,
        "auth0": args.auth0,
        "user": args.user,
    }
    chosen = [name for name, enabled in mapping.items() if enabled]
    if args.all or not chosen:
        return list(mapping.keys())
    return chosen


async def main(demos_to_run: list[str]) -> None:
    """Run requested demos in order."""
    logger.info("\n%s", "#" * 70)
    logger.info("#  JWT Library Demo - Profile-Based Architecture")
    logger.info("%s", "#" * 70)

    if "architecture" in demos_to_run:
        await demo_architecture_summary()
    if "auth0" in demos_to_run:
        await demo_auth0_token_validation()
    if "user" in demos_to_run:
        await demo_user_token()

    logger.info("\n%s", "=" * 70)
    logger.info("Demo complete!")
    logger.info("%s\n", "=" * 70)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    cli_args = build_parser().parse_args()
    asyncio.run(main(selected_demos(cli_args)))