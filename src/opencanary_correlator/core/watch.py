"""Checks that only a window can answer: silence, and a rate of losses.

Every other service message is produced by a failure that has just happened. Two
are not:

* **A canary that went quiet.** Nothing arrives, so there is no event to react
  to. The only witnesses are the last-seen times the ingest path records in
  memory (`presence`) and the heartbeat each replica already publishes once a
  minute (`core.stats`).
* **A rate of drops or rejections.** One malformed payload is noise; forty a
  minute is a sender, a queue or a channel that stopped working.

Constraints:

* **One silence check per interval, from one replica.** The election is the same
  `store.lock` the digest uses, with no wait: a replica that loses does nothing.
  Every replica publishes its own node evidence, so a node is silent only when
  none of them saw it. The ingestion report is the opposite case - the counters
  are process-local, so electing one replica would silence the losses that
  happen on the others - and it relies on the notifier's per-subject cooldown
  instead.
* **No per-event cost.** Nothing here is on the ingest path; the registry write
  it reads is one dict assignment.
* **No storm.** A partition that silences a whole estate must not send one
  message per canary: the first `SILENT_PER_CHECK` are reported individually and
  the rest in one summary. The notifier's per-subject cooldown takes care of the
  next interval.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Final

from prometheus_client import REGISTRY

from opencanary_correlator import metrics
from opencanary_correlator.audit import AuditLogger
from opencanary_correlator.config import Settings
from opencanary_correlator.core.service_messages import ServiceKind, ServiceNotifier
from opencanary_correlator.presence import NODE_FIELD_PREFIX
from opencanary_correlator.storage import keys
from opencanary_correlator.storage.redis_store import RedisStore

#: A check that needs longer than this is pathological; its lock expires anyway.
WATCH_LOCK_TTL_MS: Final[int] = 60_000
#: The election needs no waiting: a replica that loses does nothing this interval.
WATCH_LOCK_WAIT_SECONDS: Final[float] = 0.0
#: Nodes reported individually per interval; the rest go into one summary.
SILENT_PER_CHECK: Final[int] = 10


def _rejected_total() -> float:
    """Payloads this process rejected, from the labelled event counter."""
    sample = REGISTRY.get_sample_value("opencanary_events_total", {"result": "rejected"})
    return float(sample or 0.0)


def _drops_by_reason() -> dict[str, float]:
    """Dropped events by reason, read off the labelled counter family.

    Reading the family rather than a fixed list of reasons means a reason added
    later shows up in the report without being registered here.
    """
    values: dict[str, float] = {}
    for family in metrics.EVENTS_DROPPED.collect():
        for sample in family.samples:
            if not sample.name.endswith("_total"):
                continue
            reason = sample.labels.get("reason", "")
            if reason:
                values[reason] = values.get(reason, 0.0) + sample.value
    return values


def _utc(epoch: int) -> str:
    """Render an epoch as a UTC timestamp, the way alerts do."""
    try:
        return datetime.fromtimestamp(epoch, tz=UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OverflowError, OSError, ValueError):  # pragma: no cover - absurd clock
        return "unknown"


def last_seen(heartbeats: Mapping[str, Mapping[str, str]]) -> dict[str, int]:
    """Newest evidence per node across the live replicas.

    A replica publishes only the nodes it tracked, so the answer is the maximum
    over the live hashes. A node that no live replica remembers is simply absent:
    after a full restart there is no evidence, and inventing silence from missing
    data would report every canary on the estate.
    """
    seen: dict[str, int] = {}
    for fields in heartbeats.values():
        for name, value in fields.items():
            if not name.startswith(NODE_FIELD_PREFIX):
                continue
            try:
                stamp = int(value)
            except (TypeError, ValueError):  # pragma: no cover - written by this package
                continue
            node = name[len(NODE_FIELD_PREFIX) :]
            if stamp > seen.get(node, 0):
                seen[node] = stamp
    return seen


class HealthWatch:
    """Report nodes that stopped delivering, from the heartbeat evidence."""

    name: Final[str] = "health_watch"

    def __init__(
        self,
        store: RedisStore,
        notifier: ServiceNotifier,
        settings: Settings,
        audit: AuditLogger,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._store = store
        self._notifier = notifier
        self._settings = settings
        self._audit = audit
        self._clock = clock
        self._task: asyncio.Task[None] | None = None
        self._stop = asyncio.Event()
        # Baselines for the ingestion report, taken at construction: the first
        # interval then covers what happened since the task started, not what
        # accumulated since the process booted hours ago.
        self._drops = _drops_by_reason()
        self._rejected = _rejected_total()

    # --- One check ----------------------------------------------------------

    async def check_once(self, now: float | None = None) -> tuple[str, ...]:
        """Run one check; return every node it found silent."""
        moment = float(self._clock() if now is None else now)
        # Process-local, and therefore before the election: a replica that loses
        # the lock still knows about the events it dropped itself.
        await self._report_ingestion()
        if self._settings.canary_silent_after <= 0:
            return ()
        async with self._store.lock(
            keys.watch_lock_key(),
            ttl_ms=WATCH_LOCK_TTL_MS,
            wait_timeout=WATCH_LOCK_WAIT_SECONDS,
        ) as acquired:
            if not acquired:
                return ()
            return await self._report_silent(moment)

    # --- Ingestion ----------------------------------------------------------

    def _ingestion_deltas(self) -> tuple[dict[str, int], int]:
        """Losses since the previous check, and advance the baseline."""
        current = _drops_by_reason()
        drops = {
            reason: int(value - self._drops.get(reason, 0.0)) for reason, value in current.items()
        }
        self._drops = current
        rejected_now = _rejected_total()
        rejected = int(rejected_now - self._rejected)
        self._rejected = rejected_now
        # A counter only falls when the process it belonged to is gone; then the
        # window starts over rather than reporting a negative count.
        return {reason: count for reason, count in drops.items() if count > 0}, max(0, rejected)

    async def _report_ingestion(self) -> None:
        """Speak when one interval lost more than the configured threshold."""
        drops, rejected = self._ingestion_deltas()
        total = sum(drops.values())
        if self._settings.service_drops_threshold > 0 and total >= (
            self._settings.service_drops_threshold
        ):
            await self._notify_drops(total, drops)
        if self._settings.service_rejections_threshold > 0 and rejected >= (
            self._settings.service_rejections_threshold
        ):
            await self._notify_rejected(rejected)

    async def _notify_drops(self, total: int, drops: Mapping[str, int]) -> None:
        """Name the reasons, because "events were dropped" is not actionable."""
        ranked = sorted(drops.items(), key=lambda item: (-item[1], item[0]))
        reasons = ", ".join(f"{reason} {count}" for reason, count in ranked[:4])
        if len(ranked) > 4:
            reasons += f", +{len(ranked) - 4} more"
        await self._notifier.notify(
            ServiceKind.INGESTION_DROPPED,
            title=f"Correlator dropped {total} events",
            lines=(
                f"Last {_minutes(self._settings.watch_interval)}",
                f"By reason: {reasons}",
                "A full queue, a dispatch path that cannot keep up or the incident "
                "store rejecting the write; the audit trail names each event.",
            ),
            subject="ingestion:dropped",
            count=total,
        )

    async def _notify_rejected(self, rejected: int) -> None:
        await self._notifier.notify(
            ServiceKind.INGESTION_REJECTED,
            title=f"Correlator rejected {rejected} payloads",
            lines=(
                f"Last {_minutes(self._settings.watch_interval)}",
                "They failed validation before correlation: a sender whose format "
                "does not match the OpenCanary schema, or a probe.",
                "`event_rejected` records carry the peer and the first schema error.",
            ),
            subject="ingestion:rejected",
            count=rejected,
        )

    async def _report_silent(self, moment: float) -> tuple[str, ...]:
        """Audit and notify every node whose newest evidence is too old."""
        seen = last_seen(await self._store.live_heartbeats())
        cutoff = moment - float(self._settings.canary_silent_after)
        silent = tuple(sorted(node for node, stamp in seen.items() if stamp <= cutoff))
        if not silent:
            return ()
        for node in silent:
            self._audit.emit(
                "canary_silent",
                "warning",
                {
                    "node_id": node,
                    "last_seen": seen[node],
                    "silent_seconds": int(moment - seen[node]),
                },
            )
        await self._notify(silent, seen, moment)
        return silent

    async def _notify(
        self, silent: tuple[str, ...], seen: Mapping[str, int], moment: float
    ) -> None:
        """Say it once per node per cooldown, and once for the overflow."""
        for node in silent[:SILENT_PER_CHECK]:
            await self._notifier.notify(
                ServiceKind.CANARY_SILENT,
                title=f"Canary {node} went silent",
                lines=(
                    f"Last event: {_utc(seen[node])}",
                    f"Silent for: {_minutes(moment - seen[node])}",
                    "No event reached the correlator since then: the honeypot, its "
                    "network path or its log handler may be down.",
                ),
                subject=f"node:{node}",
            )
        rest = silent[SILENT_PER_CHECK:]
        if rest:
            await self._notifier.notify(
                ServiceKind.CANARY_SILENT,
                title=f"{len(silent)} canaries went silent",
                lines=(
                    f"First {SILENT_PER_CHECK} reported individually",
                    "Also silent: " + ", ".join(rest[:20]) + ("..." if len(rest) > 20 else ""),
                ),
                subject="canary:bulk",
                count=len(rest),
            )

    # --- Scheduling ---------------------------------------------------------

    async def start(self) -> None:
        """Start the loop that checks once per `OCC_WATCH_INTERVAL`."""
        if self._task is None:
            self._task = asyncio.create_task(self._loop(), name="health-watch")

    async def stop(self) -> None:
        """Wake the loop, cancel it and wait for it to unwind."""
        task, self._task = self._task, None
        self._stop.set()
        if task is None:
            return
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

    async def _loop(self) -> None:
        interval = float(self._settings.watch_interval)
        while not self._stop.is_set():
            if await self._wait(interval):
                return
            try:
                await self.check_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # a broken check must not kill the process
                # The interval is retried, not shortened: a Redis outage would
                # otherwise turn into a retry loop that hammers it.
                self._audit.emit("health_watch_failed", "error", {"error_type": type(exc).__name__})

    async def _wait(self, delay: float) -> bool:
        """Sleep up to `delay` seconds; return True when a stop was requested."""
        if delay <= 0:  # pragma: no cover - the setting is bounded from below
            return self._stop.is_set()
        try:
            await asyncio.wait_for(self._stop.wait(), timeout=delay)
        except TimeoutError:
            return False
        return True


def _minutes(seconds: float) -> str:
    """Render a silence duration in the unit an operator thinks in."""
    total = int(max(0.0, seconds))
    if total < 3600:
        return f"{total // 60} min"
    hours, rest = divmod(total, 3600)
    if hours < 48:
        return f"{hours} h {rest // 60} min"
    return f"{hours // 24} days"


__all__ = [
    "SILENT_PER_CHECK",
    "WATCH_LOCK_TTL_MS",
    "HealthWatch",
    "last_seen",
]
