import logging
import os
import asyncio

from jwt_lib.authenticator import Auth0Authenticator
from jwt_lib.claims import TrustedClaims
from jwt_lib.validation import RequireScopes
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

logger = logging.getLogger("jwt_lib.auth0_token_example")

async def main():
    """Demo: Validating Auth0 token."""
    
    logger.info("\n%s", "=" * 70)
    scope_rules: RequireScopes = RequireScopes(["update:core"])

    # cache_ttl controls how long JWKS keys are cached in memory (seconds).
    # Omit it to use the library default (300 s). Override per-environment as needed.
    authenticator: Auth0Authenticator = Auth0Authenticator(
        issuer=os.getenv("AUTH_0_ISSUER", ""),
        jwks_host=os.getenv("AUTH_0_JWKS_HOST", ""),
        audience=os.getenv("AUTH_0_AUDIENCE"),
        profile_kwargs={"app_name": "lmr-db-client"},
        cache_ttl=float(os.getenv("JWKS_CACHE_TTL", "300")),
    )
    try:
        claims: TrustedClaims = await authenticator.validate(
            os.getenv("AUTH_0_TOKEN", ""),
            extra_rules=[scope_rules],
        )
        logger.info("\n✓ Signature + standard claims validated via Auth0JWTVerifier")
        logger.info("✓ Auth0 profile validation passed (grant type, appName, azp, optional scopes)")
        
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
