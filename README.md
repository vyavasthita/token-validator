# jwt_lib
JWT Token Validation library.

## Architecture:

Tokens flow through three simple roles:

1. **`JWTVerifier` (cryptographic trust)** — fetches JWKS, enforces issuer/audience/temporal claims, verifies the signature, and returns trusted payloads.

2. **`TokenProfile` (business rules)** — defines which domain rules apply to the trusted claims (e.g., `tokenType`, `principalType`, workspace/model requirements, header checks) and when to run them. Profiles can also accept extra runtime rules (scopes, entitlements) supplied by callers.

3. **`ClaimValidator` (rule engine)** — executes the ordered list of `ClaimRule` objects for a profile and any extra rules, handling short-circuiting and consistent error reporting so profiles don’t repeat that plumbing.

4. **`Authenticator` (orchestration)** — pairs a verifier with a profile so clients call a single `validate()`; helper builders in `jwt_lib.src.authenticator` hide issuer/audience/JWKS wiring for common token flavors while still allowing overrides.

Keeping the responsibilities separate keeps the crypto path minimal, allows new token flavors without touching the verifier, and keeps tests focused (integration for the verifier, fast unit tests for each profile/rule set).

## Test the lib independently

### Go to packages/python
```bash
cd packages/python
```

### Install Packages
```bash
poetry install
```

### Running tests
```bash
poetry run pytest
```

### Running the demo script
```bash
poetry run python main.py
```

**Usage as lib in another service**

## How to install
Add following in your pyproject.toml
jwt-lib = { git = "https://github.com/vyavasthita/jwt-lib.git", branch = "main", subdirectory = "packages/python" }


```python
from jwt_lib.src.authenticator import UserAuthenticator

authenticator = UserAuthenticator(
	profile_kwargs={"require_workspace_id": True}
)

claims = await authenticator.validate(token)  # Verifier + profile run together
```