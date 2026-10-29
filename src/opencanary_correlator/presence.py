"""Last-seen times per canary, kept in this process only.

A node going silent is visible only by absence, and absence cannot be noticed on
the event path: something has to remember when each node last *did* arrive. A
Redis write per event would add a round trip to every event, so the memory lives
in the process and travels to the other replicas once a minute, inside the
heartbeat the digest already writes (`core.stats.StatsReporter`).

The registry is bounded on purpose, and a node it has never seen is refused once
it is full instead of evicting a known one: a peer that spoofs `node_id` values
must not be able to push a real canary out of the map and silence its report.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Final

#: Nodes one process tracks. Beyond this a *new* node id is ignored: the oldest
#: eviction policy would let a flood of invented ids hide the real estate.
DEFAULT_NODE_LIMIT: Final[int] = 10_000
#: Nodes one heartbeat publishes - the most recently active ones. A deployment
#: with more canaries than this still reports the ones that matter, and the
#: per-replica hash stays a few tens of kilobytes.
PUBLISH_LIMIT: Final[int] = 1_000
#: Field prefix inside the per-replica heartbeat hash. `collect_digest` skips it,
#: so the numeric totals keep their meaning.
NODE_FIELD_PREFIX: Final[str] = "node:"


class NodeRegistry:
    """The last time each node delivered an accepted event."""

    def __init__(
        self,
        *,
        limit: int = DEFAULT_NODE_LIMIT,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._limit = max(1, limit)
        self._clock = clock
        self._seen: dict[str, int] = {}

    def __len__(self) -> int:
        """How many nodes are tracked."""
        return len(self._seen)

    def touch(self, node_id: str, *, now: float | None = None) -> bool:
        """Record that `node_id` just delivered.

        Returns False when the node was refused because the registry is full.
        That answer is only informative for a test or a caller that wants to
        count it; the ingest path ignores it on purpose, because a rejected
        bookkeeping entry must never cost an event.
        """
        if not node_id:
            return False
        if node_id not in self._seen and len(self._seen) >= self._limit:
            return False
        self._seen[node_id] = int(self._clock() if now is None else now)
        return True

    def snapshot(self, *, limit: int = PUBLISH_LIMIT) -> dict[str, int]:
        """The `limit` most recently seen nodes, newest first."""
        if limit <= 0:
            return {}
        newest = sorted(self._seen.items(), key=lambda item: item[1], reverse=True)[:limit]
        return dict(newest)


__all__ = [
    "DEFAULT_NODE_LIMIT",
    "NODE_FIELD_PREFIX",
    "PUBLISH_LIMIT",
    "NodeRegistry",
]
