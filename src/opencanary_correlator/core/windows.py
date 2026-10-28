"""Time-window primitives backed by Redis.

Every primitive is keyed in Redis, so any number of correlator replicas can
share the same windows. No in-process state is kept between events.
"""

from __future__ import annotations

import hashlib
import json
from typing import Final
from uuid import uuid4

from opencanary_correlator.schemas import CanaryEvent
from opencanary_correlator.storage.redis_store import RedisStore


def event_fingerprint(event: CanaryEvent) -> str:
    """Stable digest of the identifying fields of an event.

    Two identical deliveries of the same canary event (for example from a
    duplicated syslog relay) hash to the same value; `src_port` is included so
    separate connections are never collapsed together.
    """
    payload = "\x1f".join(
        (
            event.node_id,
            event.src_host,
            str(event.src_port),
            event.dst_host,
            str(event.dst_port),
            str(int(event.logtype)),
            json.dumps(event.logdata, sort_keys=True, separators=(",", ":"), default=str),
        )
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class SlidingWindow:
    """Scored window that drops entries older than a horizon."""

    def __init__(self, store: RedisStore, key: str, *, horizon: float) -> None:
        self._store = store
        self._key = key
        self._horizon = horizon

    async def add(self, member: str, *, timestamp: float) -> int:
        """Record `member` at `timestamp` and return the window size."""
        return await self._store.zadd_window(
            self._key,
            member,
            score=timestamp,
            min_score=timestamp - self._horizon,
            ttl=self._horizon,
        )


class DistinctSetWindow:
    """Set of distinct values with a fixed TTL, as used by port-scan detection."""

    def __init__(self, store: RedisStore, key: str, *, ttl: float) -> None:
        self._store = store
        self._key = key
        self._ttl = ttl

    async def add(self, member: str) -> int:
        """Add a member and return the number of distinct members.

        The set's TTL is anchored when the window is created and is not extended
        by later members, so sustained scanning cannot keep it alive forever.
        """
        return await self._store.sadd_with_fixed_expire(self._key, member, ttl=self._ttl)

    async def members(self) -> set[str]:
        """Return the current members."""
        return await self._store.smembers(self._key)

    async def clear(self) -> None:
        """Forget the window."""
        await self._store.delete(self._key)


#: How long a claim is held before the work is done. A claim is written before
#: the rules run, so it must not be held for the whole window: a process that
#: dies in between would suppress the redelivery for `OCC_DEDUP_TTL`. Ten seconds
#: is far longer than a correlation and short enough that a restart recovers.
DEFAULT_DEDUP_LEASE: Final[float] = 10.0


class DedupCache:
    """Cross-replica deduplication for event fingerprints.

    A claim is taken as a short lease and confirmed only once the event has been
    correlated, so "we are working on it" and "it is done" are different states.
    """

    def __init__(
        self,
        store: RedisStore,
        *,
        ttl: float,
        lease: float = DEFAULT_DEDUP_LEASE,
    ) -> None:
        self._store = store
        self._ttl = ttl
        # A lease longer than the window would keep a claim alive past its TTL.
        self._lease = min(lease, ttl) if ttl > 0 else lease

    async def claim(self, fingerprint: str) -> str | None:
        """Take the claim for this fingerprint, or return None if it is held.

        The returned token is required to confirm or release it, which is what
        stops a replica from extending a claim the lease already handed over.
        """
        token = uuid4().hex
        if self._ttl <= 0:
            return token
        acquired = await self._store.acquire_dedup(
            fingerprint, ttl=max(self._lease, 0.001), token=token
        )
        return token if acquired else None

    async def confirm(self, fingerprint: str, token: str) -> bool:
        """Extend the claim to the full window once the event was correlated."""
        if self._ttl <= 0:
            return True
        return await self._store.confirm_dedup(fingerprint, ttl=self._ttl, token=token)

    async def release(self, fingerprint: str, token: str) -> None:
        """Withdraw a claim whose correlation produced nothing.

        Without this, an event whose rules failed is suppressed for the whole
        TTL: a redelivery from a second relay, or from a canary that reconnects,
        is discarded as a duplicate of work that never happened.
        """
        if self._ttl <= 0:
            return
        await self._store.release_dedup(fingerprint, token=token)


__all__ = [
    "DEFAULT_DEDUP_LEASE",
    "DedupCache",
    "DistinctSetWindow",
    "SlidingWindow",
    "event_fingerprint",
]
