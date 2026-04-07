import logging
import os
import asyncio

from jwt_lib.authenticator import UserAuthenticator
from jwt_lib.claims import TrustedClaims
from jwt_lib.validation import RequireRole
from jwt_lib.exceptions import (
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
)

logger = logging.getLogger("jwt_lib.user_token_example")

async def main():
    """Demo: Validating User Tokens."""
    logger.info("\n%s", "=" * 70)
    role_rule = RequireRole(["user"])

    try:
        authenticator: UserAuthenticator = UserAuthenticator(
            issuer=os.getenv("AUTH_USER_ISSUER", ""),
            jwks_host=os.getenv("AUTH_USER_JWKS_HOST", ""),
            audience=os.getenv("AUTH_USER_AUDIENCE", ""),
        )
        claims: TrustedClaims = await authenticator.validate(
            os.getenv("AUTH_TOKEN", ""),
            extra_rules=[role_rule],
        )
        logger.info("\n✓ Step 1: Signature + standard claims validated via UserJWTVerifier")
        logger.info("✓ Step 2: Profile validated (%s)", authenticator.profile.profile_name)
        logger.info("✓ Step 3: Role rule validated (admin required)")
        
        logger.info("--- Claims values ---")
        for key, value in claims.items():
            logger.info(f"Key={key}, value={value}")
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

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
