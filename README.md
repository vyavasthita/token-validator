# jwt_lib
JWT Token Validation library.

## Documentation

- Architecture overview: [packages/python/docs/architecture.md](packages/python/docs/architecture.md)


**Usage as lib in another service**

## How to install
Add following in your pyproject.toml
jwt-lib = { git = "https://github.com/vyavasthita/jwt-lib.git", branch = "main", subdirectory = "packages/python" }


```python
from jwt_lib.src.authenticator import UserAuthenticator

authenticator = UserAuthenticator(
	issuer="https://auth.anaplan.com",
	jwks_host="https://auth.anaplan.com",
)

claims = await authenticator.validate(token)  # UserJWTVerifier + UserProfile run together
```

### TrustedClaims object
`validate()` returns a `TrustedClaims` instance (see [packages/python/jwt_lib/src/claims/trusted_claims.py](packages/python/jwt_lib/src/claims/trusted_claims.py)). It behaves like a read-only dict and offers convenience properties:

- `claims.subject` → `sub`
- `claims.issuer` → `iss`
- `claims.audience` → `aud` (string or list)
- `claims.expiration` → `exp` (Unix timestamp)
- `claims.issued_at` → `iat`
- `claims.not_before` → `nbf`
- `claims.jwt_id` → `jti`
- `claims.headers` → copy of the JOSE header
- `claims.get_header("kid")` → header helper
- `claims.to_dict()` → shallow copy of all claims

It also implements `Mapping`, so `claims["custom"]` and `claims.get("custom")` work for domain-specific fields.

**Test the lib independently**

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

**Running the demo script**

- The demo expects live tokens provided via environment variables. 
- Export the set that matches the token type you want to validate, then run the script.

#### User Token Demo (In `main.py`)
- `AUTH_USER_ISSUER` – Issuer URL (must match the `iss` claim including trailing slash).
- `AUTH_USER_JWKS_HOST` – Host that serves the JWKS document.
- `AUTH_USER_AUDIENCE` – Audience string expected in the token (optional if your tokens omit `aud`).
- `AUTH_TOKEN` – Encoded JWT to validate.

Example:
```bash
export AUTH_USER_ISSUER="https://login.example.com/"
export AUTH_USER_JWKS_HOST="https://login.example.com/"
export AUTH_USER_AUDIENCE="my-first-party-app"
export AUTH_TOKEN="<jwt here>"
poetry run python main.py
```

#### Auth0 Token Demo (In `main.py`)
- `AUTH_0_ISSUER` – Auth0 issuer URL (e.g., `https://tenant.auth0.com/`).
- `AUTH_0_JWKS_HOST` – Hostname that exposes the JWKS set (usually same as issuer).
- `AUTH_0_AUDIENCE` – API audience configured in Auth0.
- `AUTH_0_TOKEN` – Encoded Auth0 access token.

Example:
```bash
export AUTH_0_ISSUER="https://tenant.auth0.com/"
export AUTH_0_JWKS_HOST="https://tenant.auth0.com/"
export AUTH_0_AUDIENCE="https://api.example.com"
export AUTH_0_TOKEN="<jwt here>"
poetry run python main.py
```
