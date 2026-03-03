import httpx
import pytest
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

from jwt_lib.exceptions import SigningKeyNotFoundError
from jwt_lib.verifier.timeout_jwk_client import AsyncJWKSFetcher


class DummyResponse:
    def __init__(self, payload, status_code=200):
        self.payload = payload
        self.status_code = status_code

    def json(self):
        return self.payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError(
                "boom",
                request=Mock(),
                response=Mock(status_code=self.status_code),
            )


async def _build_fetcher(monkeypatch, responses, ttl=30.0):
    fetcher = AsyncJWKSFetcher("https://example.com/.well-known/jwks.json", cache_ttl=ttl, max_retries=0)
    client = SimpleNamespace(get=AsyncMock(side_effect=responses))
    monkeypatch.setattr(fetcher, "_get_client", AsyncMock(return_value=client))
    return fetcher, client


@pytest.mark.asyncio
async def test_fetch_serves_cached_response_within_ttl(monkeypatch):
    current_time = {"value": 0.0}

    def fake_monotonic():
        return current_time["value"]

    monkeypatch.setattr("jwt_lib.verifier.timeout_jwk_client.time.monotonic", fake_monotonic)

    first = DummyResponse({"keys": ["fresh"]})
    second = DummyResponse({"keys": ["stale"]})
    fetcher, client = await _build_fetcher(monkeypatch, [first, second])

    body_one = await fetcher.fetch()
    current_time["value"] += 1.0  # within TTL
    body_two = await fetcher.fetch()

    assert body_one == body_two == {"keys": ["fresh"]}
    assert client.get.await_count == 1


@pytest.mark.asyncio
async def test_fetch_refreshes_after_ttl_expiry(monkeypatch):
    current_time = {"value": 0.0}

    def fake_monotonic():
        return current_time["value"]

    monkeypatch.setattr("jwt_lib.verifier.timeout_jwk_client.time.monotonic", fake_monotonic)

    first = DummyResponse({"keys": ["first"]})
    second = DummyResponse({"keys": ["second"]})
    fetcher, client = await _build_fetcher(monkeypatch, [first, second], ttl=1.0)

    body_one = await fetcher.fetch()
    current_time["value"] += 2.0  # beyond TTL
    body_two = await fetcher.fetch()

    assert body_one != body_two
    assert client.get.await_count == 2


@pytest.mark.asyncio
async def test_fetch_retries_and_raises(monkeypatch):
    fetcher = AsyncJWKSFetcher("https://example.com/jwks", max_retries=1)

    async def failing_get(_):
        raise httpx.HTTPError("network boom")

    client = SimpleNamespace(get=failing_get)
    monkeypatch.setattr(fetcher, "_get_client", AsyncMock(return_value=client))

    with pytest.raises(SigningKeyNotFoundError):
        await fetcher.fetch()


@pytest.mark.asyncio
async def test_async_close_closes_underlying_client():
    fetcher = AsyncJWKSFetcher("https://example.com/jwks")
    mock_client = AsyncMock()
    fetcher._client = mock_client

    await fetcher.async_close()

    mock_client.aclose.assert_awaited_once()
    assert fetcher._client is None
