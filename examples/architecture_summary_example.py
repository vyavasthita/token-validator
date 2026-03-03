import logging

logger = logging.getLogger("jwt_lib.architecture_summary_example")

def main():
    """
    Logs a visual summary of the recommended JWT verification architecture, including:

    - An ASCII diagram showing the flow from JWT token to claims and business logic profiles
    - Rationale for the design (SRP, Open/Closed, Encapsulation, Testability)
    - Example usage pattern for verifier and profile separation

    This function demonstrates how to communicate architecture and best practices via logging.
    """
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
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │  Auth0/User JWTVerifiers (Single Responsibility)              │  │
│  │  • JWKS signature verification                                │  │
│  │  • Standard claims: exp, nbf, iss, aud                        │  │
│  │  • User-only hooks: kid, typ, iat policies                    │  │
│  └───────────────────────────────────────────────────────────────┘  │
│        │                                                            │
│        ▼ TrustedClaims                                              │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │  TokenProfile (Strategy Pattern: Business Logic)              │  │
│  │  • UserProfile                                                │  │
│  │  • Auth0Profile                                               │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
    """)
    logger.info("""
WHY THIS DESIGN?

✓ SRP: Verifier handles crypto, Profile handles business rules
✓ Open/Closed: Add new profiles without modifying verifier
✓ Encapsulation: Domain knowledge in profiles, not client code
✓ Testability: Each component can be tested independently
""")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()