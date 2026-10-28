"""Time windows and counters.

The expiry is the whole point of this module: a sliding TTL turns a window into
an ever-extending one under constant traffic, so every method here writes the
expiry once and never refreshes it, except where refreshing is the intended
behaviour and says so.
"""

from __future__ import annotations

from opencanary_correlator.storage._base import _StoreBase


class _WindowsMixin(_StoreBase):
    """Set, ZSET and counter windows with a fixed expiry."""

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


__all__ = ["_WindowsMixin"]
