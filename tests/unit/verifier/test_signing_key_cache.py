
# New tests for public cache-related methods
import asyncio
import base64
from collections import OrderedDict

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from unittest.mock import AsyncMock

from jwt_lib.verifier.base_verifier import JWTVerifier, SigningKeyNotFoundError


class DummyVerifier(JWTVerifier):
    async def validate(self, token: str):  # pragma: no cover - not used
        raise NotImplementedError


def make_jwk(kid):
    """Utility to generate a deterministic RSA JWK for tests."""

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    numbers = public_key.public_numbers()
    n = numbers.n
    e = numbers.e

    def to_base64url_uint(val):
        b = val.to_bytes((val.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

    return {
        "kty": "RSA",
        "kid": kid,
        "alg": "RS256",
        "use": "sig",
        "n": to_base64url_uint(n),
        "e": to_base64url_uint(e),
    }


@pytest.mark.asyncio
async def test_verify_non_cached_key_caches_on_success(monkeypatch):
    verifier = DummyVerifier("iss", "host", ["RS256"])
    kid = "abc123"
    jwk = make_jwk(kid)
    monkeypatch.setattr(verifier._jwks_fetcher, "fetch", AsyncMock(return_value={"keys": [jwk]}))
    monkeypatch.setattr(verifier, "_decode_and_verify", lambda token, key: {"sub": "user"})

    claims = await verifier.verify_non_cached_key("token", kid)

    assert kid in verifier._SIGNING_KEY_CACHE
    assert claims == {"sub": "user"}


@pytest.mark.asyncio
async def test_verify_non_cached_key_does_not_cache_on_failure(monkeypatch):
    verifier = DummyVerifier("iss", "host", ["RS256"])
    kid = "abc123"
    verifier._SIGNING_KEY_CACHE.clear()
    monkeypatch.setattr(verifier._jwks_fetcher, "fetch", AsyncMock(side_effect=SigningKeyNotFoundError("boom")))

    with pytest.raises(SigningKeyNotFoundError):
        await verifier.verify_non_cached_key("token", kid)

    assert kid not in verifier._SIGNING_KEY_CACHE


@pytest.mark.asyncio
async def test_verify_cached_key_uses_cache_and_recovers(monkeypatch):
    verifier = DummyVerifier("iss", "host", ["RS256"])
    kid = "abc123"
    key_obj = object()
    verifier._SIGNING_KEY_CACHE[kid] = key_obj

    from jwt_lib.exceptions import InvalidTokenError

    calls = []

    def decode(token, key):
        calls.append(key)
        if len(calls) == 1:
            raise InvalidTokenError("fail decode")
        return {"sub": "user"}

    monkeypatch.setattr(verifier, "_decode_and_verify", decode)
    monkeypatch.setattr(verifier, "verify_non_cached_key", AsyncMock(return_value={"sub": "user"}))

    claims = await verifier.verify_cached_key("token", kid, key_obj)

    assert claims == {"sub": "user"}
    assert calls[0] == key_obj


@pytest.mark.asyncio
async def test_cache_hit_refreshes_lru_order(monkeypatch):
    verifier = DummyVerifier("iss", "host", ["RS256"])
    verifier._SIGNING_KEY_CACHE.update(OrderedDict([("old", object()), ("hot", object())]))
    monkeypatch.setattr(verifier, "_decode_and_verify", lambda token, key: {"sub": "user"})

    await verifier.verify_cached_key("token", "hot", verifier._SIGNING_KEY_CACHE["hot"])

    assert list(verifier._SIGNING_KEY_CACHE.keys())[-1] == "hot"


@pytest.mark.asyncio
async def test_cache_is_isolated_per_instance(monkeypatch):
    v1 = DummyVerifier("iss1", "host1", ["RS256"])
    v2 = DummyVerifier("iss2", "host2", ["RS256"])

    jwk1 = make_jwk("kid")
    jwk2 = make_jwk("kid")
    monkeypatch.setattr(v1._jwks_fetcher, "fetch", AsyncMock(return_value={"keys": [jwk1]}))
    monkeypatch.setattr(v2._jwks_fetcher, "fetch", AsyncMock(return_value={"keys": [jwk2]}))
    monkeypatch.setattr(v1, "_decode_and_verify", lambda *args, **kwargs: {"sub": "one"})
    monkeypatch.setattr(v2, "_decode_and_verify", lambda *args, **kwargs: {"sub": "two"})

    await v1.verify_non_cached_key("token", "kid")

    assert "kid" in v1._SIGNING_KEY_CACHE
    assert "kid" not in v2._SIGNING_KEY_CACHE


@pytest.mark.asyncio
async def test_parallel_cache_reads_share_same_key(monkeypatch):
    verifier = DummyVerifier("iss", "host", ["RS256"])
    kid = "parallel"
    jwk = make_jwk(kid)
    fetch_mock = AsyncMock(return_value={"keys": [jwk]})
    monkeypatch.setattr(verifier._jwks_fetcher, "fetch", fetch_mock)
    monkeypatch.setattr(verifier, "_decode_and_verify", lambda token, key: {"sub": token})

    async def worker(token_value: str):
        return await verifier.verify_non_cached_key(token_value, kid)

    results = await asyncio.gather(worker("a"), worker("b"))

    assert all(res["sub"] in {"a", "b"} for res in results)
    assert len(verifier._SIGNING_KEY_CACHE) == 1

