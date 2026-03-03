# token-validator
JWT Token Validation library.

## About
Python lib to validate JWT user token and Auth0 token.

---

## Documentation

- Architecture overview: [docs/architecture.md](docs/architecture.md)

---

## Usage as a Library in Another Service
### Option 1: Using Poetry dependency
Add the following in your `pyproject.toml`:

```toml
jwt-lib = { git = "https://github.com/vyavasthita/token-validator.git", branch = "main" }
```

### Option 2: Install via Poetry (client usage)
- Add the dependency directly:
    ```bash
    poetry add "git+https://github.com/vyavasthita/token-validator.git"
    ```
---

## Test the Library Independently

### Go to repo root
```bash
cd token-validator
```

### Install Packages
```bash
poetry install --extras test
```

- The optional `test` extra pulls in pytest helpers only for local development, so the published package stays lean.
- The same command applies when someone clones this repository directly (for example, to run the examples or tests); installing with `--extras test` ensures the helpers are present without bundling them in the published wheel.

---

## Running Examples

- Standalone example scripts are available in the `examples/` directory. 
- Each script demonstrates a specific use case and can be run directly after setting the required environment variables.

Go to dir, if not already in.
```bash
cd token-validator
```

### User Token Validation Example

Set the following environment variables:

```bash
export AUTH_USER_ISSUER="https://login.example.com/"
export AUTH_USER_JWKS_HOST="https://login.example.com/"
export AUTH_USER_AUDIENCE="my-first-party-app"
export AUTH_TOKEN="<jwt here>"
```
Then run:

```bash
poetry run python examples/user_token_validation_example.py
```

### Auth0 Token Validation Example

Set the following environment variables:

```bash
export AUTH_0_ISSUER="https://tenant.auth0.com/"
export AUTH_0_JWKS_HOST="https://tenant.auth0.com/"
export AUTH_0_AUDIENCE="https://api.example.com"
export AUTH_0_TOKEN="<jwt here>"
```
Then run:

```bash
poetry run python examples/auth0_token_validation_example.py
```

### Architecture Summary Example

No environment variables are required. Run:
```bash
poetry run python examples/architecture_summary_example.py
```

### Running tests
```bash
poetry run pytest
```