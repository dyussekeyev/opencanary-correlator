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
from opencanary_correlator.storage.keys import (
    INCIDENTS_CREATED,
    NODES_LAST_SEEN,
    STATS_INSTANCE_PREFIX,
)

#: Heartbeats read in one digest. A deployment with more replicas than this is
#: not what the correlator is built for; the cap keeps the read bounded anyway.
MAX_HEARTBEATS: int = 500


class _StatsMixin(_StoreBase):
    """Write and read replica heartbeats, and read the incident window."""

    async def write_heartbeat(self, key: str, fields: Mapping[str, Any], *, ttl: float) -> None:
        """Replace one replica's counters and refresh its expiry atomically."""
        async with self._client.pipeline(transaction=True) as pipe:
            pipe.delete(key)
            pipe.hset(key, mapping={field: str(value) for field, value in fields.items()})
            pipe.expire(key, max(1, int(ttl)))
            await pipe.execute()

    async def flush_statistics(
        self, generation: str, counters: Mapping[str, int], *, now: float
    ) -> None:
        """Idempotent cumulative checkpoint + minute deltas in one transaction.

        Buckets live eight days; checkpoints nine. A process must flush at least
        once per nine days. Counters are assigned to flush time, not event time.
        """
        body = """
for i = 1, #ARGV, 2 do
    local previous = tonumber(redis.call('HGET', KEYS[1], ARGV[i]) or '0')
    local current = tonumber(ARGV[i+1])
    if current > previous then
        redis.call('HINCRBY', KEYS[2], ARGV[i], current - previous)
        redis.call('HSET', KEYS[1], ARGV[i], current)
    end
end
redis.call('EXPIRE', KEYS[1], 777600)
if redis.call('EXISTS', KEYS[2]) == 1 then redis.call('EXPIRE', KEYS[2], 691200) end
return 1
"""
        from typing import cast

        from redis.commands.core import Script

        args = [item for name, value in counters.items() for item in (name, str(value))]
        await self._run_script(
            cast(Script, self._client.register_script(body)),
            [f"stats:v2:checkpoint:{generation}", f"stats:v2:minute:{int(now // 60)}"],
            args,
        )

    async def statistics_between(self, *, start: float, end: float) -> dict[str, int]:
        """Sum [start,end) flush buckets, bounded to eight days.

        A day is 1440 buckets, so they are read in one pipelined round trip
        rather than 1440 sequential ones.
        """
        first = max(int(start // 60), int(end // 60) - 11520)
        minutes = range(first, int(end // 60))
        if not minutes:
            return {}
        async with self._client.pipeline(transaction=False) as pipe:
            for minute in minutes:
                pipe.hgetall(f"stats:v2:minute:{minute}")
            replies = await pipe.execute()
        totals: dict[str, int] = {}
        for fields in replies:
            for raw_name, value in fields.items():
                name = self._text(raw_name)
                totals[name] = totals.get(name, 0) + int(value)
        return totals

    async def flush_node_activity(self, nodes: Mapping[str, int], *, limit: int = 10000) -> int:
        """Merge monotonic last-seen; refuse new identities beyond a global cap."""
        from typing import cast

        from redis.commands.core import Script

        body = """
local refused = 0
for i = 2, #ARGV, 2 do
    local previous = redis.call('ZSCORE', KEYS[1], ARGV[i])
    if previous or redis.call('ZCARD', KEYS[1]) < tonumber(ARGV[1]) then
        if not previous or tonumber(ARGV[i+1]) > tonumber(previous) then
            redis.call('ZADD', KEYS[1], ARGV[i+1], ARGV[i])
        end
    else refused = refused + 1 end
end
return refused
"""
        args = [str(limit), *[item for node, stamp in nodes.items() for item in (node, str(stamp))]]
        return int(
            await self._run_script(
                cast(Script, self._client.register_script(body)), [NODES_LAST_SEEN], args
            )
        )

    async def node_activity(self) -> dict[str, int]:
        values = await self._client.zrange(NODES_LAST_SEEN, 0, 9999, withscores=True)
        return {self._text(node): int(stamp) for node, stamp in values}

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

    async def count_new_incidents(self, *, start: float, end: float) -> int:
        """Creations inside the window whose incident still exists.

        The mark outlives the hash when an operator deletes a false positive by
        hand, so counting marks alone reports incidents that no longer exist.
        """
        return int(
            await self._run_script(
                self._count_live_created_script, [INCIDENTS_CREATED], [str(start), str(end)]
            )
        )

    async def count_incidents(self, *, start: float, end: float) -> int:
        """Incidents whose newest event lies inside `[start, end]`."""
        return int(await self._client.zcount(KEY_INCIDENTS, start, end))

    async def incidents_between(self, *, start: float, end: float, limit: int) -> list[str]:
        """Newest incident keys inside the window, capped by `limit`."""
        values = await self._client.zrevrangebyscore(
            KEY_INCIDENTS, end, start, start=0, num=max(1, int(limit))
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
