"""Shared HTTP dispatcher plumbing.

Each channel gets bounded retries with exponential backoff and jitter, honours
``Retry-After``, and can share a Redis-backed circuit breaker so replicas stop
hammering an endpoint that is already known to be down.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import random
from abc import abstractmethod
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import httpx
from redis.exceptions import RedisError

from opencanary_correlator.connectors.base import BaseDispatcher, DispatchResult, IncidentLike
from opencanary_correlator.storage.redis_store import RedisStore

_MAX_RETRY_AFTER_SECONDS = 60.0

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    """Retry behaviour for a delivery channel."""

    attempts: int = 3
    base_delay: float = 0.5
    max_delay: float = 5.0
    jitter: float = 0.1


def endpoint_fingerprint(endpoint: str) -> str:
    """Return a stable, non-reversible identifier for a channel endpoint."""
    return hashlib.sha256(endpoint.encode("utf-8")).hexdigest()[:16]


def breaker_name(channel: str, endpoint: str) -> str:
    """Return the Redis breaker name for one concrete endpoint.

    Webhook URLs and Telegram bot URLs contain secrets, so only a truncated
    SHA-256 of the endpoint is persisted; the raw URL/chat id never appears in
    Redis keys or audit output.
    """
    return f"{channel}:{endpoint_fingerprint(endpoint)}"


class CircuitBreaker:
    """Redis-backed breaker shared by every replica."""

    def __init__(
        self,
        store: RedisStore,
        name: str,
        *,
        failure_threshold: int = 5,
        cooldown: float = 60.0,
    ) -> None:
        self._store = store
        self._name = name
        self._failure_threshold = max(1, failure_threshold)
        self._cooldown = cooldown

    @property
    def _failure_key(self) -> str:
        return f"breaker:{self._name}:failures"

    @property
    def _open_key(self) -> str:
        return f"breaker:{self._name}:open"

    async def allow(self) -> bool:
        """Return False while the breaker is open."""
        return not await self._store.exists(self._open_key)

    async def record_failure(self) -> None:
        """Count a failure and open the breaker at the threshold."""
        failures = await self._store.increment_with_expire(self._failure_key, ttl=self._cooldown)
        if failures >= self._failure_threshold:
            await self._store.set_with_ttl(self._open_key, "1", ttl=self._cooldown)

    async def record_success(self) -> None:
        """Reset the failure counter after a successful delivery."""
        await self._store.delete(self._failure_key, self._open_key)


class HTTPDispatcher(BaseDispatcher):
    """Deliver incidents to a JSON HTTP endpoint."""

    name = "http"

    def __init__(
        self,
        *,
        url: str,
        client: httpx.AsyncClient | None = None,
        timeout: float = 10.0,
        retry: RetryPolicy | None = None,
        breaker: CircuitBreaker | None = None,
        headers: Mapping[str, str] | None = None,
        expected_status: Sequence[int] = (200,),
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._url = url
        self._client = client if client is not None else httpx.AsyncClient(timeout=timeout)
        self._owns_client = client is None
        self._retry = retry or RetryPolicy()
        self._breaker = breaker
        self._headers = dict(headers or {})
        self._expected = frozenset(expected_status)
        self._sleep = sleep

    async def aclose(self) -> None:
        """Close the HTTP client if this dispatcher created it."""
        if self._owns_client:
            await self._client.aclose()

    @abstractmethod
    def build_payload(self, incident: IncidentLike) -> dict[str, Any]:
        """Render the JSON body for one incident."""

    async def _breaker_allows(self) -> bool:
        """True unless the breaker says the endpoint is known to be down.

        The breaker lives in Redis, so reading it can fail on its own. Breaker
        state is an optimisation that protects a remote endpoint; it must never
        decide whether an alert is delivered, and a Redis outage must not turn a
        healthy channel into a skipped delivery.
        """
        if self._breaker is None:
            return True
        try:
            return await self._breaker.allow()
        except RedisError:
            logger.warning("circuit breaker %s is unavailable; delivering anyway", self._breaker)
            return True

    async def _record_breaker(self, *, failed: bool) -> None:
        """Update the breaker, ignoring a storage failure.

        A failure to *count* an outcome must not change the reported outcome: a
        delivered alert that cannot record its success has still been delivered.
        """
        if self._breaker is None:
            return
        try:
            if failed:
                await self._breaker.record_failure()
            else:
                await self._breaker.record_success()
        except RedisError:
            logger.warning("circuit breaker %s state could not be updated", self._breaker)

    async def dispatch(self, incident: IncidentLike) -> DispatchResult:
        """POST the payload with retries, never raising."""
        if not await self._breaker_allows():
            return DispatchResult(dispatcher=self.name, status="skipped", detail="circuit_open")

        payload = self.build_payload(incident)
        detail = "no_attempt"
        for attempt in range(1, self._retry.attempts + 1):
            retry_after: float | None = None
            try:
                response = await self._client.post(self._url, json=payload, headers=self._headers)
            except httpx.HTTPError as exc:
                detail = type(exc).__name__
            else:
                if response.status_code in self._expected:
                    await self._record_breaker(failed=False)
                    return DispatchResult(dispatcher=self.name, status="success")
                detail = f"http_{response.status_code}"
                if response.status_code != 429 and not 500 <= response.status_code < 600:
                    return DispatchResult(dispatcher=self.name, status="error", detail=detail)
                retry_after = self._parse_retry_after(response)

            if attempt < self._retry.attempts:
                await self._sleep(self._delay(attempt, retry_after))

        await self._record_breaker(failed=True)
        return DispatchResult(dispatcher=self.name, status="error", detail=detail)

    def _delay(self, attempt: int, retry_after: float | None) -> float:
        if retry_after is not None:
            return retry_after
        delay = min(self._retry.base_delay * (2 ** (attempt - 1)), self._retry.max_delay)
        if self._retry.jitter:
            delay += random.uniform(0, self._retry.jitter * delay)  # noqa: S311 - jitter only
        return float(delay)

    @staticmethod
    def _parse_retry_after(response: httpx.Response) -> float | None:
        value = response.headers.get("Retry-After")
        if value is None:
            return None
        try:
            seconds = float(value)
        except ValueError:
            return None
        return max(0.0, min(seconds, _MAX_RETRY_AFTER_SECONDS))


__all__ = [
    "CircuitBreaker",
    "HTTPDispatcher",
    "RetryPolicy",
    "breaker_name",
    "endpoint_fingerprint",
]
