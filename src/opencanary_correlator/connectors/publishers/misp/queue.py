"""Durable per-window MISP observation queue in Redis.

The queue is intentionally separate from the notification outbox: a full alert
budget or a broken chat channel must not lose an observation, and a retry of one
daily MISP window must not re-send notifications. Each window is one Redis hash
whose fields are source addresses; a Lua script merges a new observation into an
existing address atomically, so several replicas can ingest the same window.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Final, cast

from redis.commands.core import Script

from opencanary_correlator.connectors.publishers.misp.models import MispObservation
from opencanary_correlator.storage.redis_store import RedisStore

MISP_WINDOW_PREFIX: Final[str] = "misp:v2:window:"
MISP_WINDOWS_INDEX: Final[str] = "misp:v2:windows"
DEFAULT_RETENTION_SECONDS: Final[int] = 14 * 24 * 3600

_MERGE_LUA: Final[str] = """
local existing = redis.call('HGET', KEYS[1], ARGV[1])
local incoming = cjson.decode(ARGV[2])
if existing then
  local current = cjson.decode(existing)
  current.count = current.count + incoming.count
  if incoming.first_seen < current.first_seen then current.first_seen = incoming.first_seen end
  if incoming.last_seen > current.last_seen then current.last_seen = incoming.last_seen end
  for key, value in pairs(incoming.services or {}) do
    current.services[key] = (current.services[key] or 0) + value
  end
  for key, value in pairs(incoming.ports or {}) do
    current.ports[key] = (current.ports[key] or 0) + value
  end
  if (current.country_code == nil or current.country_code == '') and incoming.country_code then
    current.country_code = incoming.country_code
  end
  if (current.country == nil or current.country == '') and incoming.country then
    current.country = incoming.country
  end
  if (current.asn == nil or current.asn == cjson.null) and incoming.asn then
    current.asn = incoming.asn
  end
  if (current.as_org == nil or current.as_org == '') and incoming.as_org then
    current.as_org = incoming.as_org
  end
  incoming = current
elseif redis.call('HLEN', KEYS[1]) >= tonumber(ARGV[6]) then
  return 0
end
redis.call('HSET', KEYS[1], ARGV[1], cjson.encode(incoming))
redis.call('ZADD', KEYS[2], ARGV[3], ARGV[4])
redis.call('EXPIRE', KEYS[1], ARGV[5])
return 1
"""


class MispQueueError(RuntimeError):
    """A queued window cannot be decoded."""


def window_key(start: datetime) -> str:
    """Redis hash key for one window, based on its UTC start epoch."""
    return f"{MISP_WINDOW_PREFIX}{int(start.astimezone(UTC).timestamp())}"


class MispObservationQueue:
    """Atomic, fixed-retention aggregation of observations by window."""

    def __init__(
        self,
        store: RedisStore,
        *,
        retention_seconds: int = DEFAULT_RETENTION_SECONDS,
        max_observations_per_window: int = 10_000,
    ) -> None:
        self._store = store
        self._retention = max(3600, int(retention_seconds))
        self._max_observations = max(1, int(max_observations_per_window))
        self._merge = cast(Script, store.client.register_script(_MERGE_LUA))

    async def enqueue(self, start: datetime, end: datetime, observation: MispObservation) -> bool:
        """Merge one observation into its window. False means the window is full."""
        key = window_key(start)
        result = await self._store._run_script(
            self._merge,
            [key, MISP_WINDOWS_INDEX],
            [
                observation.ip,
                observation.model_dump_json(),
                str(int(end.astimezone(UTC).timestamp())),
                str(int(start.astimezone(UTC).timestamp())),
                str(self._retention),
                str(self._max_observations),
            ],
        )
        return bool(result)

    async def pending(self, now: datetime, *, limit: int = 100) -> list[datetime]:
        """Window starts whose end is at or before `now`, oldest first."""
        epoch = int(now.astimezone(UTC).timestamp())
        members = await self._store.zrangebyscore(
            MISP_WINDOWS_INDEX, "-inf", epoch, limit=max(1, limit)
        )
        starts: list[datetime] = []
        for raw in members:
            try:
                starts.append(datetime.fromtimestamp(int(raw), tz=UTC))
            except (OverflowError, OSError, ValueError):
                continue
        return starts

    async def read(self, start: datetime) -> list[MispObservation]:
        """Read every observation in a window, sorted by source address."""
        fields = await self._store.hgetall(window_key(start))
        observations: list[MispObservation] = []
        for raw in fields.values():
            try:
                observations.append(MispObservation.model_validate_json(raw))
            except Exception as exc:  # pydantic and JSON errors both mean corruption
                raise MispQueueError("corrupt_window") from exc
        return sorted(observations, key=lambda item: item.ip)

    async def ack(self, start: datetime) -> None:
        """Remove a window only after its event was created and tagged."""
        key = window_key(start)
        async with self._store.client.pipeline(transaction=True) as pipe:
            pipe.delete(key)
            pipe.zrem(MISP_WINDOWS_INDEX, str(int(start.astimezone(UTC).timestamp())))
            await pipe.execute()

    async def pending_count(self) -> int:
        """Number of windows waiting, used by metrics and tests."""
        return int(await self._store.client.zcard(MISP_WINDOWS_INDEX))

    async def window_end(self, start: datetime) -> datetime | None:
        """Read the recorded close time of a window."""
        score = await self._store.client.zscore(
            MISP_WINDOWS_INDEX, str(int(start.astimezone(UTC).timestamp()))
        )
        if score is None:
            return None
        return datetime.fromtimestamp(float(score), tz=UTC)


__all__ = [
    "DEFAULT_RETENTION_SECONDS",
    "MISP_WINDOWS_INDEX",
    "MISP_WINDOW_PREFIX",
    "MispObservationQueue",
    "MispQueueError",
    "window_key",
]
