"""Replica heartbeats and the numbers one daily digest needs.

Two constraints decide the shape:

* **No hot-path cost.** Counting an event in Redis would add a round trip to
  every event, so each replica publishes its *already maintained* process-local
  Prometheus counters once a minute into a hash with a TTL. The digest sums the
  live hashes, and a replica that died stops contributing on its own.
* **One message per day, from one replica.** The digest is elected with a lock
  and a `SET NX` marker, so the number of replicas does not multiply the number
  of messages.

The incident side is not counted twice either: it is read from the legacy
``incidents`` ZSET, whose scores are exactly the timestamps the window needs.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final

from prometheus_client import REGISTRY

from opencanary_correlator import __version__, metrics
from opencanary_correlator.audit import AuditLogger
from opencanary_correlator.constants import INCIDENT_KEY_PREFIX
from opencanary_correlator.presence import NODE_FIELD_PREFIX, NodeRegistry
from opencanary_correlator.storage import keys
from opencanary_correlator.storage.redis_store import RedisStore

#: How often a replica refreshes its heartbeat, and how long it stays visible.
HEARTBEAT_INTERVAL: Final[float] = 60.0
HEARTBEAT_TTL: Final[float] = 300.0

#: Event results summed into the digest, in the order they are rendered.
EVENT_RESULTS: Final[tuple[str, ...]] = (
    "accepted",
    "rejected",
    "dropped",
    "rate_limited",
    "deduplicated",
    "unrouted",
    "ignored",
)

#: Alert delivery outcomes summed into the digest.
ALERT_STATUSES: Final[tuple[str, ...]] = ("success", "error", "timeout", "skipped")

#: Incidents inspected to rank the busiest sources. The digest lists at most
#: `OCC_DIGEST_TOP_SOURCES`, but the ranking needs more than that to be honest.
DIGEST_SCAN_LIMIT: Final[int] = 1000

#: `incident:<type>:<src_host>:<timestamp>` -> the prefix that starts such a key.
_PREFIXES: Final[tuple[str, ...]] = tuple(INCIDENT_KEY_PREFIX.values())


def _sample(name: str, labels: Mapping[str, str] | None = None) -> float:
    """Read one Prometheus counter value, treating an absent sample as zero."""
    value = REGISTRY.get_sample_value(name, dict(labels or {}))
    return float(value or 0.0)


def _sum_total(metric: object) -> float:
    """Sum every `_total` sample of a counter, whatever its labels are."""
    collect = getattr(metric, "collect", None)
    if collect is None:  # pragma: no cover - every metric here is a Counter
        return 0.0
    return float(
        sum(
            sample.value
            for family in collect()
            for sample in family.samples
            if sample.name.endswith("_total")
        )
    )


@dataclass(frozen=True, slots=True)
class DigestData:
    """What the correlator did during one digest window."""

    start: int
    end: int
    replicas: int
    events: Mapping[str, int]
    incidents: int
    alerts: Mapping[str, int]
    rule_failures: int
    top_sources: tuple[tuple[str, int], ...]
    quota_day: int
    quota_month: int

    @property
    def total_events(self) -> int:
        """Events the replicas accepted inside the window."""
        return self.events.get("accepted", 0)


class StatsReporter:
    """Publish this replica's counters for the digest to sum."""

    name: Final[str] = "stats"

    def __init__(
        self,
        store: RedisStore,
        audit: AuditLogger,
        *,
        instance_id: str | None = None,
        clock: Callable[[], float] = time.time,
        nodes: NodeRegistry | None = None,
    ) -> None:
        self._store = store
        self._audit = audit
        self._instance = instance_id or uuid.uuid4().hex
        self._clock = clock
        self._started = float(self._clock())
        # Without a registry the heartbeat carries counters only, which is what a
        # digest-only deployment needs; the silence check needs the registry.
        self._nodes = nodes
        self._task: asyncio.Task[None] | None = None

    @property
    def instance_id(self) -> str:
        """Id of this replica, as the digest sees it."""
        return self._instance

    @property
    def key(self) -> str:
        """Redis key of this replica's heartbeat."""
        return keys.stats_instance_key(self._instance)

    def snapshot(self) -> dict[str, int | str]:
        """What is known right now, from the process-local counters."""
        fields: dict[str, int | str] = {
            "version": __version__,
            "started": int(self._started),
            "rule_failures": int(_sum_total(metrics.RULE_FAILURES)),
        }
        # One field per result, so the digest can show the breakdown without the
        # reporter deciding which results matter.
        for result in EVENT_RESULTS:
            fields[f"events_{result}"] = int(_sample("opencanary_events_total", {"result": result}))
        for status in ALERT_STATUSES:
            fields[f"alerts_{status}"] = int(_sample("opencanary_alerts_total", {"status": status}))
        if self._nodes is not None:
            # `node:<id>` -> the last epoch that node delivered an event. The
            # digest skips the prefix; the silence check is its only reader.
            for node_id, last_seen in self._nodes.snapshot().items():
                fields[f"{NODE_FIELD_PREFIX}{node_id}"] = last_seen
        return fields

    async def beat(self) -> None:
        """Publish one heartbeat, replacing the previous counters."""
        await self._store.write_heartbeat(self.key, self.snapshot(), ttl=HEARTBEAT_TTL)

    async def start(self) -> None:
        """Publish a first heartbeat now, then refresh it on a timer."""
        if self._task is not None:
            return
        await self._beat_quietly()
        self._task = asyncio.create_task(self._loop(), name="stats-heartbeat")

    async def stop(self) -> None:
        """Cancel the heartbeat loop and wait for it to unwind."""
        task, self._task = self._task, None
        if task is None:
            return
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

    async def _loop(self) -> None:
        while True:
            await asyncio.sleep(HEARTBEAT_INTERVAL)
            await self._beat_quietly()

    async def _beat_quietly(self) -> None:
        """A missed heartbeat costs a digest field, never the process."""
        try:
            await self.beat()
        except Exception as exc:
            self._audit.emit(
                "stats_heartbeat_failed", "warning", {"error_type": type(exc).__name__}
            )


def _source_of(incident_key: str) -> str | None:
    """Extract the attacker address from `incident:<type>:<src_host>:<ts>`.

    The host is everything between the type prefix and the last colon, which
    keeps an IPv6 address (it contains colons of its own) intact.
    """
    for prefix in _PREFIXES:
        if incident_key.startswith(prefix):
            rest = incident_key[len(prefix) :]
            host, separator, _stamp = rest.rpartition(":")
            return host if separator and host else None
    return None


def _sum_heartbeat(instance: str, fields: Mapping[str, str], totals: dict[str, int]) -> None:
    """Add one replica's counters to the digest totals."""
    for name, value in fields.items():
        if name in {"version", "started"} or name.startswith(NODE_FIELD_PREFIX):
            # Node evidence is not a counter: summing it would produce totals
            # nobody asked for and lose the per-node meaning at the same time.
            continue
        try:
            totals[name] = totals.get(name, 0) + int(value)
        except ValueError:  # pragma: no cover - written by this module
            continue


async def collect_digest(
    store: RedisStore,
    *,
    now: float | None = None,
    top_sources: int = 5,
    window: float = 24 * 3600.0,
) -> DigestData:
    """Build the digest for the trailing `window` ending now."""
    moment = float(time.time() if now is None else now)
    end = int(moment)
    start = int(moment - window)

    heartbeats = await store.live_heartbeats()
    totals: dict[str, int] = {}
    for instance, fields in heartbeats.items():
        _sum_heartbeat(instance, fields, totals)

    incidents = await store.count_incidents(start=start, end=end)
    sources: dict[str, int] = {}
    if top_sources > 0:
        for incident_key in await store.incidents_between(
            start=start, end=end, limit=DIGEST_SCAN_LIMIT
        ):
            host = _source_of(incident_key)
            if host is not None:
                sources[host] = sources.get(host, 0) + 1
    ranked = tuple(
        sorted(sources.items(), key=lambda item: (-item[1], item[0]))[: max(0, top_sources)]
    )

    stamp = datetime.fromtimestamp(moment, tz=UTC)
    quota_day = await _read_counter(store, "day", stamp.strftime("%Y%m%d"))
    quota_month = await _read_counter(store, "month", stamp.strftime("%Y%m"))

    return DigestData(
        start=start,
        end=end,
        replicas=len(heartbeats),
        events={result: totals.get(f"events_{result}", 0) for result in EVENT_RESULTS},
        incidents=incidents,
        alerts={status: totals.get(f"alerts_{status}", 0) for status in ALERT_STATUSES},
        rule_failures=totals.get("rule_failures", 0),
        top_sources=ranked,
        quota_day=quota_day,
        quota_month=quota_month,
    )


async def _read_counter(store: RedisStore, window: str, stamp: str) -> int:
    """Read one quota counter, treating a missing key as zero."""
    raw = await store.get_value(keys.quota_key("virustotal", window, stamp))
    try:
        return int(raw) if raw is not None else 0
    except ValueError:  # pragma: no cover - the counter is written by the client
        return 0


__all__ = [
    "ALERT_STATUSES",
    "DIGEST_SCAN_LIMIT",
    "EVENT_RESULTS",
    "HEARTBEAT_INTERVAL",
    "HEARTBEAT_TTL",
    "DigestData",
    "StatsReporter",
    "collect_digest",
]
