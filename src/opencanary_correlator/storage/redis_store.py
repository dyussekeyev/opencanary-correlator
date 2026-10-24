"""Async Redis access layer.

All correlation state lives here so replicas stay stateless. Multi-step writes
(window updates) go through transactional pipelines, incident persistence and
the lock release run as Lua scripts (one atomic round trip each), and incident
creation is serialised with a short-lived distributed lock, because a lost
update would mean a duplicate alert. Incident lookup uses a per-host pointer so
it does not have to walk the whole ``incidents`` index on every event.

The client targets one logical Redis server. Redis Cluster is not supported:
:meth:`save_incident` writes an ``incident:*`` hash, the ``incidents`` ZSET and
the host pointer, which are different Cluster slots (``CROSSSLOT``).
Hash-tagging them would change the legacy key layout, so use a primary/replica
or failover endpoint.
"""

from __future__ import annotations

import asyncio
import contextlib
import uuid
from collections.abc import AsyncIterator, Awaitable, Mapping, Sequence
from contextlib import asynccontextmanager
from typing import Any, cast

from redis.asyncio import Redis
from redis.commands.core import Script
from redis.exceptions import RedisError

from opencanary_correlator.constants import KEY_INCIDENTS, KEY_LOGS
from opencanary_correlator.storage.keys import dedup_key

DEFAULT_LOCK_TTL_MS: int = 5_000
DEFAULT_LOCK_WAIT_SECONDS: float = 5.0
LOCK_RETRY_INTERVAL_SECONDS: float = 0.01

#: Release a lock only while it still holds our token, in one round trip.
#: A GET followed by DEL is racy (a TTL expiry in between would delete the new
#: owner's lock); WATCH does the same job in five commands per event.
_RELEASE_LOCK_LUA = """
if redis.call('GET', KEYS[1]) == ARGV[1] then
    return redis.call('DEL', KEYS[1])
end
return 0
"""

#: Write the incident hash, its index entry and the per-host pointer atomically.
#: MULTI would need five commands per incident; one script does the same work in
#: one round trip. ARGV[1] is the score, ARGV[2] the pointer value, and the
#: remaining arguments are the hash field/value pairs.
_SAVE_INCIDENT_LUA = """
redis.call('HSET', KEYS[1], unpack(ARGV, 3))
redis.call('ZADD', KEYS[2], ARGV[1], KEYS[1])
if KEYS[3] then
    redis.call('HSET', KEYS[3], 'key', ARGV[2], 'score', ARGV[1])
end
return 1
"""


class RedisStore:
    """Typed wrapper around `redis.asyncio.Redis` used by the correlator."""

    def __init__(self, client: Redis) -> None:
        self._client = client
        self._release_lock_script = cast(Script, client.register_script(_RELEASE_LOCK_LUA))
        self._save_incident_script = cast(Script, client.register_script(_SAVE_INCIDENT_LUA))

    @classmethod
    def from_url(cls, url: str) -> RedisStore:
        """Create a store for one logical server from a supported Redis URL.

        ``redis://``, ``rediss://`` and ``unix://`` select a regular
        ``redis.asyncio.Redis`` client. Redis Cluster is not supported because
        one incident write script touches an incident hash, the ``incidents``
        index and the host pointer, which live in different slots; see the
        module docstring.
        """
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

    async def sadd_with_fixed_expire(self, key: str, member: str, *, ttl: float) -> int:
        """Add `member` to a set and return its cardinality without sliding the TTL.

        The expiry is written once, when the set is created (or when an existing
        key lost its TTL); later members must not extend a port-scan window, or
        continuous scanning would keep the threshold window alive forever.
        """
        async with self._client.pipeline(transaction=True) as pipe:
            pipe.sadd(key, member)
            pipe.ttl(key)
            pipe.scard(key)
            results = await pipe.execute()
        if int(results[1]) < 0:
            await self._client.expire(key, max(1, int(ttl)))
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

    async def find_recent_incident(
        self,
        prefix: str,
        *,
        min_score: float,
        pointer_key: str | None = None,
    ) -> str | None:
        """Return the newest incident key starting with `prefix` created after `min_score`.

        ``ZREVRANGEBYSCORE`` has to transfer every incident in the window and
        filter them in Python, which turns ingestion into O(incidents) work per
        event - 10k incidents meant a 10k-element response per event.

        `pointer_key` is the O(1) shortcut: a small hash holding the incident
        :meth:`save_incident` last wrote for this prefix and its score. The
        pointer is only a hint. A missing pointer (an incident created by an
        older replica, or one whose TTL expired) and an outdated score both
        fall back to the authoritative ZSET scan, so the legacy index stays the
        source of truth during rolling upgrades.
        """
        if pointer_key is not None:
            pointer = await self.hgetall(pointer_key)
            pointed = pointer.get("key")
            if pointed is not None and pointed.startswith(prefix):
                try:
                    pointer_score = float(pointer.get("score", ""))
                except ValueError:
                    pointer_score = float("-inf")
                if pointer_score >= min_score:
                    return pointed
        for key in await self.zrevrangebyscore(KEY_INCIDENTS, "+inf", min_score):
            if key.startswith(prefix):
                return key
        return None

    async def save_incident(
        self,
        key: str,
        fields: Mapping[str, str],
        *,
        score: float,
        pointer_key: str | None = None,
    ) -> None:
        """Persist the incident hash and refresh its score in the index ZSET.

        The hash, the index and the optional per-host `pointer_key` are written
        by one Lua script, so they are atomic and cost a single round trip.
        The script holds several keys, which requires them to live on the same
        server: Redis Cluster would reject it with ``CROSSSLOT``, and the
        deployment contract is a single logical Redis.
        """
        keys = [key, KEY_INCIDENTS] + ([pointer_key] if pointer_key is not None else [])
        pairs: list[str] = []
        for field, value in fields.items():
            pairs.append(field)
            pairs.append(value)
        await self._run_script(
            self._save_incident_script,
            keys,
            [str(score), key, *pairs],
        )

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
                    await self._release_lock(key, token)

    async def _release_lock(self, key: str, token: str) -> bool:
        """Delete `key` only while it still holds `token`, atomically.

        A plain GET followed by DEL is racy: if the TTL expires between the two
        calls, another replica can acquire the lock and the first replica would
        delete the new owner's lock. The script compares and deletes in one
        atomic round trip.
        """
        released = await self._run_script(self._release_lock_script, [key], [token])
        return bool(released)

    async def _run_script(
        self,
        script: Script,
        keys: Sequence[str],
        args: Sequence[str],
    ) -> Any:
        """Run a registered script, awaiting its reply.

        redis-py types `Script` against the synchronous client only, so the call
        is cast to the awaitable it returns for an async client.
        """
        pending = cast(Awaitable[Any], script(keys=keys, args=args))
        return await pending


__all__ = ["RedisStore"]
