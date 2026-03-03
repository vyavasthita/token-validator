# Contributing

Thanks for helping improve `token-validator`! 

This guide summarizes how to set up a local environment, run the automated suite, and propose changes.

## Prerequisites
- Python 3.12+
- [Poetry](https://python-poetry.org/docs/) 1.8 or newer

## Environment Setup
1. Clone the repository and `cd token-validator`.
2. Install dependencies including the optional `test` extra:
   ```bash
   poetry install --extras test
   ```
3. Activate the virtual environment if you prefer an interactive shell:
   ```bash
   poetry shell
   ```

## Running Tests
Execute the entire test suite before opening a pull request:
```bash
poetry run pytest
```

## Code Style
- Keep code in the `src/jwt_lib/` package; tests belong under `tests/`.
- Favor small, focused commits with descriptive messages.
- Add or update tests for any functional change.

## Documentation & Examples
- Update `README.md` or files under `docs/` when you add features that affect users.
- Example scripts live in `examples/`; feel free to add new scenarios when relevant.

## Submitting Changes
1. Create a feature branch.
2. Ensure `poetry run pytest` passes without failures.
3. Open a pull request describing the motivation, key changes, and test results.

We appreciate your contributions!