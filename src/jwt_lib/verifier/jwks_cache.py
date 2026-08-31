"""Unified JWKS key cache with configurable TTL and refresh-on-miss.

Design goals:
    - Production-grade: handles key rotation, concurrent requests, and
      transient network failures gracefully.
    - Single source of truth: one dictionary holds ALL currently-valid keys.
    - Atomic replacement: removed keys disappear immediately after refresh.
    - Configurable: the consuming service controls the TTL via constructor.

Cache behaviour:
    Normal path (hot cache):
        get_key(kid) → dict lookup → return key  (no HTTP call)

    Cache expired:
        get_key(kid) → detect expiry → acquire lock → fetch JWKS → parse
        all keys → atomically swap dict → return key

    Refresh-on-miss (key rotation):
        get_key(kid) → dict lookup misses → acquire lock → fetch JWKS →
        parse all keys → atomically swap dict → retry lookup → return or raise
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Callable, Dict

import httpx
from jwt.algorithms import RSAAlgorithm

from jwt_lib.exceptions import SigningKeyNotFoundError


logger = logging.getLogger(__name__)


class JWKSCache:
    """Unified in-memory JWKS key cache.

    Maintains a single dict mapping kid → parsed RSA public key object.
    The entire dict is atomically replaced on every successful JWKS refresh.

    Parameters
    ----------
    jwks_url:
        Full URL to the JWKS endpoint (e.g. https://auth.example.com/.well-known/jwks.json).
    cache_ttl:
        Seconds before the cache is considered stale and a refresh is triggered.
        Default: 300 (5 minutes). The consuming service controls this value.
    timeout:
        HTTP request timeout in seconds for JWKS fetches.
    max_retries:
        Number of retry attempts on transient HTTP failures (exponential backoff).
    headers_provider:
        Optional callback returning extra HTTP headers (e.g. trace context) to
        include in JWKS requests for distributed tracing.
    """

    def __init__(
        self,
        jwks_url: str,
        cache_ttl: float = 300.0,
        timeout: float = 5.0,
        max_retries: int = 2,
        headers_provider: Callable[[], Dict[str, str]] | None = None,
    ) -> None:
        self._jwks_url = jwks_url
        self._cache_ttl = max(0.0, cache_ttl)
        self._timeout = timeout
        self._max_retries = max(0, max_retries)
        self._headers_provider = headers_provider

        # The atomic cache: replaced entirely on every refresh.
        self._key_cache: dict[str, Any] = {}

        # Monotonic timestamp of last successful refresh (0 = never refreshed).
        self._last_refresh: float = 0.0

        # Ensures only one coroutine refreshes at a time.
        self._lock = asyncio.Lock()

        # Reusable httpx client for connection pooling.
        self._client: httpx.AsyncClient | None = None

    # ── Public API ────────────────────────────────────────────────────────────
    # Entry points for callers: key retrieval and lifecycle management.
    # All other methods in this class are internal implementation details.

    @property
    def jwks_url(self) -> str:
        """The JWKS endpoint URL."""
        return self._jwks_url

    async def get_key(self, kid: str) -> Any:
        """Retrieve the parsed public key for the given kid.

        This is the main entry point called on every token validation.

        Flow:
            1. If cache is fresh → dict lookup → return if found.
            2. If cache is stale → refresh → dict lookup → return if found.
            3. If kid not found → refresh-on-miss → retry → return or raise.
        """
        # Fast path: cache is fresh and kid is present.
        if self._is_cache_fresh():
            key = self._key_cache.get(kid)

            if key is not None:
                logger.debug(f"JWKS cache hit for kid={kid}")
                return key

            # kid not in fresh cache → refresh-on-miss.
            return await self._refresh_on_miss(kid)

        # Cache is stale — refresh, then lookup.
        await self._locked_refresh()

        key = self._key_cache.get(kid)

        if key is not None:
            logger.debug(f"JWKS cache hit for kid={kid} (after refresh)")
            return key

        # Still not found after scheduled refresh → try refresh-on-miss.
        return await self._refresh_on_miss(kid)

    async def close(self) -> None:
        """Close the reusable httpx client for clean shutdown."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    # ── Cache State & Expiry ──────────────────────────────────────────────────
    # Determines whether the in-memory cache is still valid and orchestrates
    # TTL-based scheduled refreshes and refresh-on-miss for key rotation.
    # Uses an asyncio.Lock (double-checked locking) so that only one coroutine
    # performs an HTTP call at a time; all others wait and reuse the result.

    def _is_cache_fresh(self) -> bool:
        """Return True if the cache was refreshed within the TTL window."""
        if not self._key_cache:
            return False

        return (time.monotonic() - self._last_refresh) < self._cache_ttl

    async def _locked_refresh(self) -> None:
        """Acquire the lock and refresh if still stale (double-check pattern).

        Multiple coroutines may detect an expired cache simultaneously. Only the
        first one to acquire the lock performs the HTTP call; subsequent waiters
        find the cache already fresh and return immediately.
        """
        async with self._lock:
            # Double-check: another coroutine may have refreshed while we waited.
            if self._is_cache_fresh():
                return

            await self._refresh()

    async def _refresh_on_miss(self, kid: str) -> Any:
        """Force a JWKS refresh when a kid is not found in the current cache.

        This handles key rotation: a new kid appears in tokens before the TTL
        expires, so we fetch immediately regardless of cache freshness.
        """
        logger.info(f"Refresh-on-miss triggered for kid={kid} url={self._jwks_url}")

        async with self._lock:
            # Double-check: another coroutine may have refreshed and added the kid.
            key = self._key_cache.get(kid)

            if key is not None:
                logger.debug(f"kid={kid} found after concurrent refresh")
                return key

            await self._refresh()

        # Final lookup after refresh.
        key = self._key_cache.get(kid)
        if key is not None:
            return key

        # kid genuinely does not exist in the JWKS document.
        available = list(self._key_cache.keys())
        logger.warning(
            f"Unknown kid={kid} after JWKS refresh url={self._jwks_url}"
            f" available_kids={available}"
        )
        raise SigningKeyNotFoundError(
            f"Signing key not found for kid={kid}. Available kids: {available}"
        )

    async def _refresh(self) -> None:
        """Fetch the JWKS document, parse all keys, and atomically swap the cache.

        On success: replaces the entire cache dict and updates the timestamp.
        On failure: keeps the existing cache (graceful degradation) if any keys
        are present; raises if the cache is empty (startup scenario).
        """
        logger.info(f"JWKS refresh started url={self._jwks_url}")
        start = time.monotonic()

        try:
            body = await self._fetch_jwks_with_retry()
        except Exception as exc:
            if self._key_cache:
                # Graceful degradation: keep serving with stale keys.
                age = time.monotonic() - self._last_refresh
                logger.warning(
                    f"JWKS refresh failed url={self._jwks_url} error={exc}"
                    f" using_stale_cache=True cache_age_seconds={age:.1f}"
                )
                return

            # No cache at all (e.g. first startup) — cannot validate tokens.
            logger.warning(
                f"JWKS refresh failed url={self._jwks_url} error={exc}"
                f" using_stale_cache=False"
            )
            raise SigningKeyNotFoundError(
                f"Failed to fetch JWKS and no cached keys available: {exc}"
            ) from exc

        self._parse_and_swap_cache(body, start)

    # ── Key Parsing ───────────────────────────────────────────────────────────
    # Transforms raw JWKS JSON into parsed RSA public key objects and performs
    # the atomic cache swap. Separated from the fetch layer so that parsing
    # logic (e.g. adding EC key support) can evolve independently.

    def _parse_and_swap_cache(self, body: dict[str, Any], start: float) -> None:
        """Parse all keys from the JWKS document and atomically replace the cache.

        Iterates every JWK entry, parses it into an RSA public key object, and
        builds a new dict. The entire cache is then replaced in one assignment so
        that removed/revoked keys disappear immediately and readers never see a
        partial state.

        Malformed individual keys are skipped with a warning; the remaining valid
        keys are still loaded so one bad JWK does not block all validation.
        """
        # Parse every key in the JWKS document into a usable public key object.
        new_cache: dict[str, Any] = {}

        for jwk in body.get("keys", []):
            kid_value = jwk.get("kid")
            if kid_value:
                try:
                    new_cache[kid_value] = RSAAlgorithm.from_jwk(jwk)
                except Exception as parse_err:
                    logger.warning(
                        f"Failed to parse JWK for kid={kid_value}: {parse_err}"
                    )

        # Atomic swap: old keys (including revoked ones) disappear immediately.
        self._key_cache = new_cache
        self._last_refresh = time.monotonic()

        duration_ms = (time.monotonic() - start) * 1000
        logger.info(
            f"JWKS refresh succeeded url={self._jwks_url}"
            f" keys_loaded={len(new_cache)} duration_ms={duration_ms:.1f}"
        )

    # ── HTTP Transport ────────────────────────────────────────────────────────
    # Handles all network I/O: a lazily-created connection-pooled httpx client
    # and exponential backoff retry logic for transient JWKS endpoint failures.

    async def _get_client(self) -> httpx.AsyncClient:
        """Lazily create (or return) the httpx client for connection reuse."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self._timeout),
                headers={"Accept": "application/json"},
            )
        return self._client

    async def _fetch_jwks_with_retry(self) -> dict[str, Any]:
        """Download the JWKS JSON with exponential backoff on failure."""
        client = await self._get_client()
        attempts = self._max_retries + 1
        backoff = 0.1
        last_error: Exception | None = None

        extra_headers = self._headers_provider() if self._headers_provider else {}

        for attempt in range(1, attempts + 1):
            try:
                response = await client.get(self._jwks_url, headers=extra_headers)
                response.raise_for_status()
                return response.json()
            except httpx.HTTPError as error:
                last_error = error
                logger.warning(
                    f"JWKS fetch attempt {attempt}/{attempts} failed"
                    f" url={self._jwks_url}: {error}"
                )
                if attempt == attempts:
                    break
                await asyncio.sleep(backoff)
                backoff *= 2

        raise last_error  # type: ignore[misc]
