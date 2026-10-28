"""The client, its scripts and the primitives every mixin builds on.

`redis.asyncio` answers with bytes for a client built with
`decode_responses=False`. `RedisStore.from_url` never does that, but a client
handed in by a caller (a test, a tool, another library) can, and before this
module the store silently answered "no value" for every string read on such a
client. Every reply now goes through :meth:`_StoreBase._text`, so the store
behaves the same way whichever client it was given.
"""

from __future__ import annotations

from collections.abc import Awaitable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Self, cast

from redis.asyncio import Redis
from redis.commands.core import Script
from redis.exceptions import RedisError

from opencanary_correlator.storage.scripts import (
    RELEASE_LOCK_LUA,
    RESERVE_QUOTA_LUA,
    SAVE_INCIDENT_LUA,
)


@dataclass(frozen=True, slots=True)
class IncidentLookup:
    """Outcome of :meth:`RedisStore.find_recent_incident`.

    ``key`` is the newest incident key for the requested prefix inside the
    horizon, or ``None`` when there is none. ``scanned`` counts how many index
    members were inspected, and ``truncated`` means the scan stopped at the cap
    before the window was exhausted - so a ``None`` key may hide an incident that
    sits further back (an older build's state, or a stale pointer).
    """

    key: str | None = None
    scanned: int = 0
    truncated: bool = False


class _StoreBase:
    """Client ownership, script registration and the shared read helpers."""

    _client: Redis
    _release_lock_script: Script
    _save_incident_script: Script
    _reserve_quota_script: Script

    def __init__(self, client: Redis) -> None:
        self._client = client
        self._release_lock_script = cast(Script, client.register_script(RELEASE_LOCK_LUA))
        self._save_incident_script = cast(Script, client.register_script(SAVE_INCIDENT_LUA))
        self._reserve_quota_script = cast(Script, client.register_script(RESERVE_QUOTA_LUA))

    @classmethod
    def from_url(cls, url: str) -> Self:
        """Create a store for one logical server from a supported Redis URL.

        ``redis://``, ``rediss://`` and ``unix://`` select a regular
        ``redis.asyncio.Redis`` client. Redis Cluster is not supported because
        one incident write script touches an incident hash, the ``incidents``
        index and the host pointer, which live in different slots; see the
        module docstring of :mod:`opencanary_correlator.storage.redis_store`.
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

    # --- Plain key operations ----------------------------------------------

    async def delete(self, *keys: str) -> int:
        """Delete keys, returning how many existed."""
        if not keys:
            return 0
        return int(await self._client.delete(*keys))

    async def exists(self, key: str) -> bool:
        """Return True when the key exists."""
        return bool(await self._client.exists(key))

    # --- Replies as text ----------------------------------------------------

    @staticmethod
    def _text(value: Any) -> str:
        """Normalise one Redis reply to text, whichever client was configured."""
        return value.decode("utf-8") if isinstance(value, bytes) else str(value)

    async def hgetall(self, key: str) -> dict[str, str]:
        """Read a hash as a plain dict."""
        pending = cast(Awaitable[Mapping[Any, Any]], self._client.hgetall(key))
        raw = await pending
        return {self._text(field): self._text(value) for field, value in raw.items()}

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
        return None if value is None else self._text(value)

    async def smembers(self, key: str) -> set[str]:
        """Read all members of a set."""
        pending = cast(Awaitable[Any], self._client.smembers(key))
        members = await pending
        return {self._text(member) for member in members}

    async def zrevrangebyscore(
        self,
        key: str,
        maximum: str,
        minimum: str | float,
        *,
        limit: int | None = None,
    ) -> list[str]:
        """Read ZSET members ordered from highest to lowest score.

        `limit` is passed to Redis as ``LIMIT 0 <limit>``, so the cap is applied
        by the server and the members beyond it are never transferred; filtering
        an unbounded reply in Python is what made the lookup O(index size).
        """
        if limit is None:
            values = await self._client.zrevrangebyscore(key, maximum, minimum)
        else:
            values = await self._client.zrevrangebyscore(
                key, maximum, minimum, start=0, num=max(1, limit)
            )
        return [self._text(value) for value in values]

    async def zrangebyscore(self, key: str, minimum: str, maximum: str) -> list[str]:
        """Read ZSET members ordered by ascending score."""
        values = await self._client.zrangebyscore(key, minimum, maximum)
        return [self._text(value) for value in values]

    # --- Scripts ------------------------------------------------------------

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


__all__ = ["IncidentLookup", "_StoreBase"]
