"""Time windows and counters.

The expiry is the whole point of this module: a sliding TTL turns a window into
an ever-extending one under constant traffic, so every method here writes the
expiry once and never refreshes it, except where refreshing is the intended
behaviour and says so.
"""

from __future__ import annotations

from typing import cast
from uuid import uuid4

from redis.commands.core import Script

from opencanary_correlator.storage._base import _StoreBase
from opencanary_correlator.storage.keys import SCAN_PENDING_INDEX


class _WindowsMixin(_StoreBase):
    """Set, ZSET and counter windows with a fixed expiry."""

    async def sadd_with_fixed_expire(self, key: str, member: str, *, ttl: float) -> int:
        """Add `member` to a set and return its cardinality without sliding the TTL.

        The expiry is written once, when the set is created (or when an existing
        key lost its TTL); later members must not extend a port-scan window, or
        continuous scanning would keep the threshold window alive forever.
        """
        script = cast(
            Script,
            self._client.register_script("""
redis.call('SADD', KEYS[1], ARGV[1])
if redis.call('PTTL', KEYS[1]) < 0 then redis.call('PEXPIRE', KEYS[1], ARGV[2]) end
return redis.call('SCARD', KEYS[1])
"""),
        )
        return int(await self._run_script(script, [key], [member, str(max(1, int(ttl * 1000)))]))

    async def snapshot_scan(
        self,
        key: str,
        *,
        member: str,
        ttl: float,
        threshold: int,
        event: str,
        now: float,
    ) -> str | None:
        """Atomically rotate threshold evidence into durable recovery state.

        New arrivals use a new active set. The pending set never expires and is
        acknowledged only by the same Lua commit that writes its incident.
        """
        pending = f"scan:v2:snapshot:{uuid4().hex}"
        script = cast(
            Script,
            self._client.register_script("""
redis.call('SADD', KEYS[1], ARGV[1])
if redis.call('PTTL', KEYS[1]) < 0 then redis.call('PEXPIRE', KEYS[1], ARGV[2]) end
local current = redis.call('GET', KEYS[5])
if current then return current end
if redis.call('SCARD', KEYS[1]) < tonumber(ARGV[3]) then return '' end
redis.call('RENAME', KEYS[1], KEYS[2])
redis.call('PERSIST', KEYS[2])
redis.call('SET', KEYS[3], ARGV[4])
redis.call('SET', KEYS[5], KEYS[2])
redis.call('SET', KEYS[2] .. ':pointer', KEYS[5])
redis.call('ZADD', KEYS[4], ARGV[5], KEYS[2])
return KEYS[2]
"""),
        )
        result = await self._run_script(
            script,
            [key, pending, pending + ":event", SCAN_PENDING_INDEX, key + ":pending"],
            [member, str(max(1, int(ttl * 1000))), str(threshold), event, str(now)],
        )
        return self._text(result) if result else None

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


__all__ = ["_WindowsMixin"]
