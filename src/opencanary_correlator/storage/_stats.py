"""Per-replica heartbeats and the incident window the digest reads.

A digest has to be produced once a day by one replica, but the numbers it reports
are spread over every replica. Counting them per event would put a Redis round
trip on the hot path, so each replica publishes its process-local counters once a
minute into its own hash with a TTL: a replica that dies simply stops
contributing, and the number of unexpired hashes is the number of live replicas.

The incident side is read straight from the legacy ``incidents`` ZSET, whose
scores are the timestamps the digest window is expressed in.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from opencanary_correlator.constants import KEY_INCIDENTS
from opencanary_correlator.storage._base import _StoreBase
from opencanary_correlator.storage.keys import STATS_INSTANCE_PREFIX

#: Heartbeats read in one digest. A deployment with more replicas than this is
#: not what the correlator is built for; the cap keeps the read bounded anyway.
MAX_HEARTBEATS: int = 500


class _StatsMixin(_StoreBase):
    """Write and read replica heartbeats, and read the incident window."""

    async def write_heartbeat(self, key: str, fields: Mapping[str, Any], *, ttl: float) -> None:
        """Replace one replica's counters and refresh its expiry atomically."""
        async with self._client.pipeline(transaction=True) as pipe:
            pipe.hset(key, mapping={field: str(value) for field, value in fields.items()})
            pipe.expire(key, max(1, int(ttl)))
            await pipe.execute()

    async def live_heartbeats(self) -> dict[str, dict[str, str]]:
        """Every unexpired replica heartbeat, keyed by its instance id.

        `SCAN` rather than `KEYS`: the latter blocks Redis for every other caller
        while it walks the keyspace, and the keyspace of a correlator holds the
        incident index too.
        """
        found: dict[str, dict[str, str]] = {}
        async for raw in self._client.scan_iter(match=f"{STATS_INSTANCE_PREFIX}*", count=100):
            if len(found) >= MAX_HEARTBEATS:
                break
            key = self._text(raw)
            fields = await self.hgetall(key)
            if fields:
                found[key[len(STATS_INSTANCE_PREFIX) :]] = fields
        return found

    async def count_incidents(self, *, start: float, end: float) -> int:
        """Incidents whose newest event lies inside `[start, end]`."""
        return int(await self._client.zcount(KEY_INCIDENTS, start, end))

    async def incidents_between(self, *, start: float, end: float, limit: int) -> list[str]:
        """Newest incident keys inside the window, capped by `limit`."""
        values = await self._client.zrangebyscore(
            KEY_INCIDENTS, start, end, start=0, num=max(1, int(limit))
        )
        return [self._text(value) for value in values]

    async def set_if_absent(self, key: str, value: str, *, ttl: float) -> bool:
        """Write `key` only when it does not exist; return whether it was written.

        One `SET NX EX` is what makes a once-a-day action exactly once even when
        every replica reaches it in the same second.
        """
        written = await self._client.set(key, value, nx=True, px=max(1, int(ttl * 1000)))
        return bool(written)


__all__ = ["MAX_HEARTBEATS", "_StatsMixin"]
