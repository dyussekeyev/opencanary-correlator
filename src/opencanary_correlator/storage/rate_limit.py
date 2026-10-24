"""Redis-backed rate limiting shared by every replica.

Budgets use fixed windows: the first request creates the counter with a TTL and
later requests only increment it. The window therefore resets on schedule even
while traffic never stops, instead of being pushed forward by every request.
"""

from __future__ import annotations

from opencanary_correlator.storage.redis_store import RedisStore

WINDOW_SECONDS = 60.0
DEFAULT_CONNECTIONS_PER_MINUTE = 60


class RedisRateLimiter:
    """Limit connections per source IP and events per node id."""

    def __init__(
        self,
        store: RedisStore,
        *,
        events_per_minute: int,
        connections_per_minute: int = DEFAULT_CONNECTIONS_PER_MINUTE,
        window_seconds: float = WINDOW_SECONDS,
    ) -> None:
        self._store = store
        self._events_per_minute = events_per_minute
        self._connections_per_minute = connections_per_minute
        self._window_seconds = window_seconds

    async def allow_connection(self, source_ip: str) -> bool:
        """Return False when `source_ip` exceeded its connection budget."""
        if self._connections_per_minute <= 0:
            return True
        count = await self._store.increment_fixed_window(
            f"ratelimit:connection:{source_ip}", ttl=self._window_seconds
        )
        return count <= self._connections_per_minute

    async def allow_event(self, node_id: str) -> bool:
        """Return False when `node_id` exceeded its event budget."""
        if self._events_per_minute <= 0:
            return True
        count = await self._store.increment_fixed_window(
            f"ratelimit:event:{node_id}", ttl=self._window_seconds
        )
        return count <= self._events_per_minute


__all__ = ["DEFAULT_CONNECTIONS_PER_MINUTE", "WINDOW_SECONDS", "RedisRateLimiter"]
