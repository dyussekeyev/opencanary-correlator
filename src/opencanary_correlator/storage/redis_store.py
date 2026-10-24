"""Async Redis access layer.

All correlation state lives here so replicas stay stateless. Multi-step writes
(window updates, incident persistence) go through transactional pipelines, and
incident creation is serialised with a short-lived distributed lock, because a
lost update would mean a duplicate alert.
"""

from __future__ import annotations

import asyncio
import contextlib
import uuid
from collections.abc import AsyncIterator, Awaitable, Mapping
from contextlib import asynccontextmanager
from typing import Any, cast

from redis.asyncio import Redis
from redis.exceptions import RedisError

from opencanary_correlator.constants import KEY_INCIDENTS, KEY_LOGS
from opencanary_correlator.storage.keys import dedup_key

DEFAULT_LOCK_TTL_MS: int = 5_000
DEFAULT_LOCK_WAIT_SECONDS: float = 5.0
LOCK_RETRY_INTERVAL_SECONDS: float = 0.01


class RedisStore:
    """Typed wrapper around `redis.asyncio.Redis` used by the correlator."""

    def __init__(self, client: Redis) -> None:
        self._client = client

    @classmethod
    def from_url(cls, url: str) -> RedisStore:
        """Create a store from a ``redis://``, ``rediss://`` or ``unix://`` URL."""
        return cls(Redis.from_url(url, decode_responses=True))

    @property
    def client(self) -> Redis:
        """The underlying client, for health checks and tests."""
        return self._client

    async def aclose(self) -> None:
        """Close the connection pool."""
        await self._client.aclose()

    async def ping(self) -> bool:
        """Return True when Redis answers PING."""
        try:
            return bool(await self._client.ping())
        except RedisError:
            return False

    # --- Deduplication ------------------------------------------------------

    async def acquire_dedup(self, fingerprint: str, *, ttl: float) -> bool:
        """Return True the first time `fingerprint` is seen within `ttl`."""
        return bool(
            await self._client.set(
                dedup_key(fingerprint),
                "1",
                nx=True,
                px=max(1, int(ttl * 1000)),
            )
        )

    # --- Windows and counters ----------------------------------------------

    async def sadd_with_expire(self, key: str, member: str, *, ttl: float) -> int:
        """Add `member` to a set and return its cardinality, refreshing the TTL."""
        async with self._client.pipeline(transaction=True) as pipe:
            pipe.sadd(key, member)
            pipe.expire(key, max(1, int(ttl)))
            pipe.scard(key)
            results = await pipe.execute()
        return int(results[2])

    async def zadd_window(
        self,
        key: str,
        member: str,
        *,
        score: float,
        min_score: float,
        ttl: float,
    ) -> int:
        """Add a scored member, trim everything older than `min_score`, return the count."""
        async with self._client.pipeline(transaction=True) as pipe:
            pipe.zadd(key, {member: score})
            pipe.zremrangebyscore(key, "-inf", min_score)
            pipe.zcard(key)
            pipe.expire(key, max(1, int(ttl)))
            results = await pipe.execute()
        return int(results[2])

    async def increment_with_expire(self, key: str, *, ttl: float) -> int:
        """Increment a counter and refresh its TTL, returning the new value.

        This is the right shape for the circuit breaker, where a continuing
        failure stream should keep the failure counter alive. Rate limiting must
        not refresh its window; use :meth:`increment_fixed_window` there.
        """
        async with self._client.pipeline(transaction=True) as pipe:
            pipe.incr(key)
            pipe.expire(key, max(1, int(ttl)))
            results = await pipe.execute()
        return int(results[0])

    async def increment_fixed_window(self, key: str, *, ttl: float) -> int:
        """Increment a fixed-window counter, setting its expiry only when created.

        Refreshing the TTL on every increment would keep a constant traffic
        source inside one ever-extending window: after exhausting its budget it
        would stay blocked until it went quiet for a full window. Here the
        expiry is written once, so the counter resets on schedule.
        """
        seconds = max(1, int(ttl))
        async with self._client.pipeline(transaction=True) as pipe:
            pipe.set(key, "0", nx=True, ex=seconds)
            pipe.incr(key)
            results = await pipe.execute()
        count = int(results[1])
        if not results[0] and count == 1:
            # The key expired between SET NX and INCR: recreate its window.
            await self._client.expire(key, seconds)
        return count

    # --- Plain reads and writes --------------------------------------------

    async def get_value(self, key: str) -> str | None:
        """Read a string key."""
        value = await self._client.get(key)
        return value if isinstance(value, str) else None

    async def set_value(self, key: str, value: str) -> None:
        """Write a string key."""
        await self._client.set(key, value)

    async def set_with_ttl(self, key: str, value: str, *, ttl: float) -> None:
        """Write a string key that expires after `ttl` seconds."""
        await self._client.set(key, value, px=max(1, int(ttl * 1000)))

    async def delete(self, *keys: str) -> int:
        """Delete keys, returning how many existed."""
        if not keys:
            return 0
        return int(await self._client.delete(*keys))

    async def exists(self, key: str) -> bool:
        """Return True when the key exists."""
        return bool(await self._client.exists(key))

    async def hgetall(self, key: str) -> dict[str, str]:
        """Read a hash as a plain dict."""
        pending = cast(Awaitable[Mapping[str, Any]], self._client.hgetall(key))
        raw = await pending
        return {str(field): str(value) for field, value in raw.items()}

    async def hset_mapping(self, key: str, mapping: Mapping[str, Any]) -> None:
        """Write several hash fields at once."""
        pending = cast(
            Awaitable[Any],
            self._client.hset(key, mapping={field: str(value) for field, value in mapping.items()}),
        )
        await pending

    async def hget(self, key: str, field: str) -> str | None:
        """Read one hash field."""
        pending = cast(Awaitable[Any], self._client.hget(key, field))
        value = await pending
        return value if isinstance(value, str) else None

    async def smembers(self, key: str) -> set[str]:
        """Read all members of a set."""
        pending = cast(Awaitable[Any], self._client.smembers(key))
        members = await pending
        return {str(member) for member in members}

    async def zrevrangebyscore(self, key: str, maximum: str, minimum: float) -> list[str]:
        """Read ZSET members ordered from highest to lowest score."""
        values = await self._client.zrevrangebyscore(key, maximum, minimum)
        return [str(value) for value in values]

    async def zrangebyscore(self, key: str, minimum: str, maximum: str) -> list[str]:
        """Read ZSET members ordered by ascending score."""
        values = await self._client.zrangebyscore(key, minimum, maximum)
        return [str(value) for value in values]

    async def lpush_trim(self, key: str, value: str, *, max_entries: int) -> None:
        """Push a log line and keep the list bounded."""
        async with self._client.pipeline(transaction=True) as pipe:
            pipe.lpush(key, value)
            pipe.ltrim(key, 0, max(0, max_entries - 1))
            await pipe.execute()

    async def push_log(self, line: str, *, max_entries: int) -> None:
        """Append a console log line to the bounded legacy `logs` list."""
        await self.lpush_trim(KEY_LOGS, line, max_entries=max_entries)

    async def lrange(self, key: str, start: int = 0, end: int = -1) -> list[str]:
        """Read a list range."""
        pending = cast(Awaitable[Any], self._client.lrange(key, start, end))
        values = await pending
        return [str(value) for value in values]

    # --- Incidents ----------------------------------------------------------

    async def find_recent_incident(self, prefix: str, *, min_score: float) -> str | None:
        """Return the newest incident key starting with `prefix` created after `min_score`."""
        for key in await self.zrevrangebyscore(KEY_INCIDENTS, "+inf", min_score):
            if key.startswith(prefix):
                return key
        return None

    async def save_incident(self, key: str, fields: Mapping[str, str], *, score: float) -> None:
        """Persist the incident hash and refresh its score in the index ZSET."""
        async with self._client.pipeline(transaction=True) as pipe:
            pipe.hset(key, mapping=dict(fields))
            pipe.zadd(KEY_INCIDENTS, {key: score})
            await pipe.execute()

    # --- Locking ------------------------------------------------------------

    @asynccontextmanager
    async def lock(
        self,
        key: str,
        *,
        ttl_ms: int = DEFAULT_LOCK_TTL_MS,
        wait_timeout: float = DEFAULT_LOCK_WAIT_SECONDS,
    ) -> AsyncIterator[bool]:
        """Acquire a best-effort distributed lock, yielding False on timeout."""
        token = uuid.uuid4().hex
        loop = asyncio.get_running_loop()
        deadline = loop.time() + wait_timeout
        acquired = False
        while True:
            acquired = bool(await self._client.set(key, token, nx=True, px=max(1, ttl_ms)))
            if acquired or loop.time() >= deadline:
                break
            await asyncio.sleep(LOCK_RETRY_INTERVAL_SECONDS)
        try:
            yield acquired
        finally:
            if acquired:
                with contextlib.suppress(RedisError):
                    current = await self._client.get(key)
                    if current == token:
                        await self._client.delete(key)


__all__ = ["RedisStore"]
