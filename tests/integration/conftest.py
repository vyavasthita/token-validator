"""Shared fixtures for integration tests."""

from __future__ import annotations

import json
from typing import Dict, Tuple

import pytest
from jwt.algorithms import RSAAlgorithm
from pytest_httpserver import HTTPServer


@pytest.fixture
def jwks_host(httpserver: HTTPServer, rsa_key_pair) -> Tuple[str, str]:
    """Expose the generated public key via the JWKS endpoint expected by the verifiers."""
    _, public_key = rsa_key_pair
    jwk: Dict[str, str] = json.loads(RSAAlgorithm.to_jwk(public_key))
    jwk["kid"] = "test-key-1"
    httpserver.expect_request("/token/.well-known/jwks.json").respond_with_json({"keys": [jwk]})
    base_url = httpserver.url_for("/").rstrip("/")
    return base_url, jwk["kid"]
