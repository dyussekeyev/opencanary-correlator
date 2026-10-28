"""The alert outbox: a decided notification either reaches a channel or is seen.

`IncidentRepository.record` enqueues one delivery per channel in the same script
that writes the incident, so a crash cannot separate the two. This module owns the
rest of the contract:

* **inline attempt** — the engine delivers immediately, as it always did, and
  reports the outcome here (`settle`), which frees the entry on success or hands
  it to the retry schedule on failure;
* **retry worker** — every replica runs one. It claims the entries that are due
  (the claim pushes each score forward by a lease, so two replicas never take the
  same entry and a dying worker simply leaves it to become due again), reloads the
  incident, delivers and either settles the entry, reschedules it with backoff or
  buries it in the dead letter list after `OCC_OUTBOX_MAX_ATTEMPTS`.

The result is at-least-once: a duplicate is possible only when a channel accepted
a message and the process died before settling it, and the delivered marker keeps
that window from being reopened by a later worker.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable, Sequence
from typing import Final

from opencanary_correlator import metrics
from opencanary_correlator.audit import AuditLogger
from opencanary_correlator.config import Settings
from opencanary_correlator.connectors.base import BaseDispatcher
from opencanary_correlator.core.delivery import deliver
from opencanary_correlator.core.incident import INCIDENT_TYPES, Incident
from opencanary_correlator.incident_specs import INCIDENT_SPECS
from opencanary_correlator.storage.keys import outbox_entry_id
from opencanary_correlator.storage.redis_store import RedisStore

#: Retry delays, in seconds. The last value repeats once it is reached.
BACKOFF_SECONDS: Final[tuple[float, ...]] = (1.0, 5.0, 30.0, 300.0, 1800.0)

#: Incident key prefix -> the class that can rebuild it.
_CLASSES_BY_PREFIX: Final[dict[str, type[Incident]]] = {
    spec.key_prefix: INCIDENT_TYPES[spec.name] for spec in INCIDENT_SPECS
}


def incident_class_for_key(key: str) -> type[Incident] | None:
    """Resolve the incident class from the key prefix the correlator wrote."""
    for prefix, incident_cls in _CLASSES_BY_PREFIX.items():
        if key.startswith(prefix):
            return incident_cls
    return None


class AlertOutbox:
    """Settlement for the inline attempt, plus the worker that retries."""

    name: Final[str] = "alert_outbox"

    def __init__(
        self,
        store: RedisStore,
        dispatchers: Sequence[BaseDispatcher],
        settings: Settings,
        audit: AuditLogger,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._store = store
        self._dispatchers = {dispatcher.name: dispatcher for dispatcher in dispatchers}
        self._settings = settings
        self._audit = audit
        self._clock = clock
        self._task: asyncio.Task[None] | None = None

    @property
    def channels(self) -> tuple[str, ...]:
        """Channels an incident is enqueued for."""
        return tuple(self._dispatchers)

    # --- Inline attempt -----------------------------------------------------

    async def settle(self, incident_key: str, channel: str, *, error: str | None) -> None:
        """Report the outcome of the attempt the engine just made.

        `error` is None when the channel accepted the message. A failure is not
        retried here: the entry gets its first attempt count and the backoff, so a
        heroically slow channel cannot turn one incident into a tight loop.
        """
        entry = outbox_entry_id(incident_key, channel)
        if error is None:
            await self._store.settle_alert(entry, retention=self._retention)
            metrics.OUTBOX_DELIVERED.labels(channel=channel).inc()
            return
        await self._store.reschedule_alert(
            entry,
            attempts=1,
            error=error,
            next_attempt=float(self._clock()) + BACKOFF_SECONDS[0],
            retention=self._retention,
        )
        metrics.OUTBOX_RETRIED.labels(channel=channel).inc()

    # --- Worker lifecycle ---------------------------------------------------

    async def start(self) -> None:
        """Start the retry loop."""
        if self._task is None:
            self._task = asyncio.create_task(self._loop(), name="alert-outbox")

    async def stop(self) -> None:
        """Cancel the retry loop and wait for it to unwind."""
        task, self._task = self._task, None
        if task is None:
            return
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

    async def run_once(self) -> int:
        """Process every delivery that is due now, returning how many succeeded."""
        now = float(self._clock())
        claimed = await self._store.claim_due_alerts(
            now=now,
            limit=self._settings.outbox_batch,
            lease=self._settings.outbox_lease,
        )
        delivered = 0
        for entry_id in claimed:
            if await self._deliver_entry(entry_id, now):
                delivered += 1
        metrics.OUTBOX_PENDING.set(await self._store.outbox_pending())
        return delivered

    async def _loop(self) -> None:
        while True:
            try:
                await self.run_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # an outbox bug must not kill the process
                self._audit.emit("outbox_failed", "error", {"error_type": type(exc).__name__})
            await asyncio.sleep(self._settings.outbox_poll_interval)

    # --- One delivery -------------------------------------------------------

    async def _deliver_entry(self, entry_id: str, now: float) -> bool:
        entry = await self._store.read_alert(entry_id)
        if entry is None:
            # Settled by another replica between the claim and the read.
            return False
        channel = entry.get("channel", "")
        incident_key = entry.get("incident", "")
        attempts = int(entry.get("attempts", "0") or 0)
        dispatcher = self._dispatchers.get(channel)
        if dispatcher is None:
            await self._bury(entry_id, incident_key, channel, attempts, "unknown_channel")
            return False
        incident = await self._load(incident_key)
        if incident is None:
            await self._bury(entry_id, incident_key, channel, attempts, "incident_gone")
            return False

        result = await deliver(
            dispatcher,
            incident,
            audit=self._audit,
            deadline=self._settings.dispatch_timeout,
        )
        if result is not None and result.status == "success":
            await self._store.settle_alert(entry_id, retention=self._retention)
            metrics.OUTBOX_DELIVERED.labels(channel=channel).inc()
            return True

        reason = "timeout" if result is None else result.status
        attempts += 1
        if attempts >= self._settings.outbox_max_attempts:
            await self._bury(entry_id, incident_key, channel, attempts, reason)
            return False
        delay = BACKOFF_SECONDS[min(attempts - 1, len(BACKOFF_SECONDS) - 1)]
        await self._store.reschedule_alert(
            entry_id,
            attempts=attempts,
            error=reason,
            next_attempt=now + delay,
            retention=self._retention,
        )
        metrics.OUTBOX_RETRIED.labels(channel=channel).inc()
        self._audit.emit(
            "alert_retry",
            "warning",
            {
                "dispatcher": channel,
                "incident": incident_key,
                "attempts": attempts,
                "reason": reason,
                "next_attempt_in": delay,
            },
        )
        return False

    async def _bury(
        self,
        entry_id: str,
        incident_key: str,
        channel: str,
        attempts: int,
        reason: str,
    ) -> None:
        await self._store.bury_alert(entry_id, attempts=attempts, error=reason)
        metrics.OUTBOX_DEAD.labels(channel=channel or "unknown").inc()
        self._audit.emit(
            "alert_dead_letter",
            "error",
            {
                "dispatcher": channel,
                "incident": incident_key,
                "attempts": attempts,
                "reason": reason,
            },
        )

    async def _load(self, incident_key: str) -> Incident | None:
        incident_cls = incident_class_for_key(incident_key)
        if incident_cls is None:
            return None
        fields = await self._store.hgetall(incident_key)
        if not fields:
            return None
        return incident_cls.from_fields(incident_key, fields)

    @property
    def _retention(self) -> float:
        return float(self._settings.outbox_delivery_retention)


__all__ = ["BACKOFF_SECONDS", "AlertOutbox", "incident_class_for_key"]
