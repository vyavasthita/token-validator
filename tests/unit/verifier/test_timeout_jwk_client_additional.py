"""Additional unit tests for AsyncJWKSFetcher behavior."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

from jwt_lib.exceptions import SigningKeyNotFoundError
from jwt_lib.verifier.timeout_jwk_client import AsyncJWKSFetcher


class _Response:
    def __init__(self, payload: dict, status_code: int = 200):
        self._payload = payload
        self._status_code = status_code

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self._status_code >= 400:
            request = httpx.Request("GET", "https://example.com/jwks")
            response = httpx.Response(self._status_code, request=request)
            raise httpx.HTTPStatusError("http error", request=request, response=response)


@pytest.mark.asyncio
async def test_fetch_retries_on_transient_503(monkeypatch):
    fetcher = AsyncJWKSFetcher("https://example.com/jwks", max_retries=1)

    client = SimpleNamespace(
        get=AsyncMock(side_effect=[_Response({}, 503), _Response({"keys": []}, 200)])
    )
    monkeypatch.setattr(fetcher, "_get_client", AsyncMock(return_value=client))

    result = await fetcher.fetch()

    assert result == {"keys": []}
    assert client.get.await_count == 2


@pytest.mark.asyncio
async def test_fetch_raises_on_http_401(monkeypatch):
    fetcher = AsyncJWKSFetcher("https://example.com/jwks", max_retries=0)

    client = SimpleNamespace(get=AsyncMock(side_effect=[_Response({}, 401)]))
    monkeypatch.setattr(fetcher, "_get_client", AsyncMock(return_value=client))

    with pytest.raises(SigningKeyNotFoundError):
        await fetcher.fetch()

    assert client.get.await_count == 1


@pytest.mark.asyncio
async def test_fetch_concurrent_calls_share_single_refresh(monkeypatch):
    fetcher = AsyncJWKSFetcher("https://example.com/jwks", cache_ttl=30.0, max_retries=0)

    async def delayed_get(_):
        return _Response({"keys": ["k1"]})

    client = SimpleNamespace(get=AsyncMock(side_effect=delayed_get))
    monkeypatch.setattr(fetcher, "_get_client", AsyncMock(return_value=client))

    first = await fetcher.fetch()
    second = await fetcher.fetch()

    assert first == {"keys": ["k1"]}
    assert second == {"keys": ["k1"]}
    assert client.get.await_count == 1
