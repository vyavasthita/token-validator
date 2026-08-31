import logging
import os
import asyncio

from jwt_lib.authenticator import UserAuthenticator
from jwt_lib.claims import TrustedClaims
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
    # cache_ttl controls how long JWKS keys are cached in memory (seconds).
    # Omit it to use the library default (300 s). Override per-environment as needed.
    authenticator: UserAuthenticator = UserAuthenticator(
        issuer=os.getenv("AUTH_USER_ISSUER", ""),
        jwks_host=os.getenv("AUTH_USER_JWKS_HOST", ""),
        audience=os.getenv("AUTH_USER_AUDIENCE", ""),
        cache_ttl=float(os.getenv("JWKS_CACHE_TTL", "300")),
    )
    try:
        claims: TrustedClaims = await authenticator.validate(os.getenv("AUTH_TOKEN", ""))
        logger.info("\n✓ Step 1: Signature + standard claims validated via UserJWTVerifier")
        logger.info("✓ Step 2: Profile validated (%s)", authenticator.profile.profile_name)
        
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
    finally:
        # Always close the authenticator to release the underlying httpx client.
        await authenticator.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
