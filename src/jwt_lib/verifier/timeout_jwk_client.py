"""Async JWKS fetching utilities with caching and retry support."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import httpx

from jwt_lib.exceptions import SigningKeyNotFoundError


logger = logging.getLogger(__name__)


class AsyncJWKSFetcher:
    """Fetch JWKS documents with connection reuse, retries, and TTL caching.

    Key improvements implemented here:

    1. Reuses a single async httpx client with tuned timeouts so TLS handshakes
       and TCP connections stay warm, reducing latency and socket churn.
    2. Maintains a lightweight in-memory JWKS cache guarded by a monotonic
       timestamp, allowing thousands of tokens to reuse one document until the
       configured TTL expires.
    3. Wraps JWKS downloads in a bounded retry loop with exponential backoff,
       tolerating brief outages while still surfacing persistent failures as
       SigningKeyNotFoundError.
    """

    def __init__(
        self,
        jwks_url: str,
        timeout: float = 5.0,
        cache_ttl: float = 30.0,
        max_retries: int = 2,
    ) -> None:
        self.jwks_url = jwks_url
        self.timeout = timeout
        self.cache_ttl = max(0.0, cache_ttl)
        self.max_retries = max(0, max_retries)
        self._client: httpx.AsyncClient | None = None
        self._cached_body: dict[str, Any] | None = None
        self._cached_at: float = 0.0

    async def _get_client(self) -> httpx.AsyncClient:
        """Create (or return) an httpx client so TCP connections stay warm."""

        if self._client is None:
            timeout = httpx.Timeout(self.timeout, connect=self.timeout, read=self.timeout)
            self._client = httpx.AsyncClient(timeout=timeout, headers={"Accept": "application/json"})
        return self._client

    def _cache_valid(self) -> bool:
        """Return True when the cached JWKS is still fresh.

        The expression checks two things in one line:
        1. `self._cached_body` must be truthy, meaning we have already fetched
           and stored a JWKS payload. If it is None, the bool short-circuits and
           returns False immediately.
        2. `(time.monotonic() - self._cached_at) < self.cache_ttl` ensures the
           elapsed monotonic time since the fetch is below the TTL. Using
           `time.monotonic()` instead of wall-clock time prevents issues if the
           system clock jumps backward or forward (e.g., NTP adjustments). For
           example, with a 30-second TTL: if we cached at t=10s and now it is
           t=35s, the delta is 25 (< 30) so the cache is valid; at t=45s the
           delta is 35, so the cache expires and we refetch.
        """

        return bool(self._cached_body and (time.monotonic() - self._cached_at) < self.cache_ttl)

    async def fetch(self) -> dict[str, Any]:
        """Retrieve JWKS JSON with cache reuse and retry semantics.

        High-level flow: serve straight from the in-memory cache when it is
        still valid; otherwise, perform up to `max_retries + 1` download
        attempts, backing off exponentially between failures, and remember the
        successful payload for future callers. If every attempt fails, we raise
        SigningKeyNotFoundError so upstream verifiers can react.
        """

        if self._cache_valid():
            logger.debug(f"Serving JWKS from cache for {self.jwks_url}")
            return self._cached_body  # type: ignore[return-value]

        attempts = self.max_retries + 1
        backoff = 0.1
        last_error: Exception | None = None

        for attempt in range(1, attempts + 1):
            # Iterate through each allowed attempt (first try + retries) until
            # we either succeed or exhaust the budget.
            try:
                client = await self._get_client()
                response = await client.get(self.jwks_url)
                response.raise_for_status()
                body: dict[str, Any] = response.json()
                self._cached_body = body
                self._cached_at = time.monotonic()
                logger.debug(
                    f"Fetched JWKS successfully on attempt {attempt}/{attempts} for {self.jwks_url}"
                )
                return body
            except httpx.HTTPError as error:
                last_error = error
                logger.warning(
                    f"JWKS fetch failed attempt {attempt}/{attempts} for {self.jwks_url}: {error}"
                )
                if attempt == attempts:
                    break
                # Simple exponential backoff so brief outages have time to recover.
                await asyncio.sleep(backoff)
                backoff *= 2

        raise SigningKeyNotFoundError("Failed to download JWKS") from last_error

    async def async_close(self) -> None:
        """Close the reusable httpx client so event loops can shut down cleanly."""

        if self._client is not None:
            await self._client.aclose()
            self._client = None
