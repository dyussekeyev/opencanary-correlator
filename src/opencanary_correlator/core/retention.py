"""Opt-in, bounded cleanup of expired state.

Retention is off by default: an upgrade must never delete history the operator
did not ask it to drop, and "we cleaned it up for you" is not something a
forensic store can say. When it is enabled, one elected replica walks a bounded
batch per interval, never touching an incident whose delivery is still owed, and
reports what it removed and what it deliberately kept.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from typing import Final

from opencanary_correlator import metrics
from opencanary_correlator.audit import AuditLogger
from opencanary_correlator.config import Settings
from opencanary_correlator.constants import INCIDENT_KEY_PREFIX, KEY_INCIDENTS
from opencanary_correlator.storage.keys import (
    OUTBOX_DEAD,
    RETENTION_LOCK,
    incident_latest_key,
)
from opencanary_correlator.storage.redis_store import RedisStore

#: How long the digest needs incident creation times; older members are pruned.
INCIDENT_CREATED_RETENTION_SECONDS: Final[float] = 8 * 24 * 3600.0


class RetentionJanitor:
    """Remove expired incidents and dead letters in bounded batches."""

    name: Final[str] = "retention"

    def __init__(
        self,
        store: RedisStore,
        settings: Settings,
        audit: AuditLogger,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._store = store
        self._settings = settings
        self._audit = audit
        self._clock = clock
        self._task: asyncio.Task[None] | None = None

    @property
    def enabled(self) -> bool:
        return self._settings.retention_enabled

    async def start(self) -> None:
        if self._task is None and self.enabled:
            self._task = asyncio.create_task(self._loop(), name="retention")

    async def stop(self) -> None:
        task, self._task = self._task, None
        if task is not None:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    @property
    def critical_tasks(self) -> tuple[asyncio.Task[None], ...]:
        """Housekeeping is never a readiness dependency."""
        return ()

    async def _loop(self) -> None:
        while True:
            try:
                await self.run_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self._audit.emit("retention_failed", "error", {"error_type": type(exc).__name__})
            await asyncio.sleep(self._settings.retention_interval)

    async def run_once(self) -> dict[str, int]:
        """Run one sweep; a replica that loses the lease does nothing."""
        summary = {"incidents": 0, "protected": 0, "stale": 0, "dead": 0, "created_pruned": 0}
        if not self.enabled:
            return summary
        ttl_ms = max(10_000, int(self._settings.retention_interval * 2000))
        async with self._store.owned_lock(
            RETENTION_LOCK, ttl_ms=ttl_ms, wait_timeout=0.01
        ) as token:
            if token is None:
                return summary
            now = float(self._clock())
            cutoff = now - self._settings.retention_days * 86400
            keys = await self._store.zrangebyscore(
                KEY_INCIDENTS, "-inf", cutoff, limit=self._settings.retention_batch
            )
            for key in keys:
                fields = await self._store.hgetall(key)
                pointer = self._pointer_key(key) if fields else ""
                outcome = await self._store.expire_incident(key, pointer_key=pointer)
                if outcome == 1:
                    summary["incidents"] += 1
                    metrics.RETENTION_REMOVED.labels(scope="incident").inc()
                elif outcome == -1:
                    summary["protected"] += 1
                    metrics.RETENTION_PROTECTED.labels(scope="incident").inc()
                else:
                    summary["stale"] += 1
            if self._settings.dlq_retention_days > 0:
                dead_cutoff = now - self._settings.dlq_retention_days * 86400
                dead_ids = await self._store.zrangebyscore(
                    OUTBOX_DEAD, "-inf", dead_cutoff, limit=self._settings.retention_batch
                )
                for entry_id in dead_ids:
                    if await self._store.expire_dead_letter(entry_id, cutoff=dead_cutoff):
                        summary["dead"] += 1
                        metrics.RETENTION_REMOVED.labels(scope="dead_letter").inc()
            summary["created_pruned"] = await self._store.prune_incident_creations(
                cutoff=now - INCIDENT_CREATED_RETENTION_SECONDS
            )
            self._audit.emit("retention_run", "info", dict(summary))
        return summary

    @staticmethod
    def _pointer_key(key: str) -> str:
        """Rebuild `incident-latest:<type>:<host>` from the incident key."""
        for name, prefix in INCIDENT_KEY_PREFIX.items():
            if key.startswith(prefix):
                host = key[len(prefix) :].rsplit(":", 1)[0]
                return incident_latest_key(name, host)
        return ""


__all__ = ["INCIDENT_CREATED_RETENTION_SECONDS", "RetentionJanitor"]
