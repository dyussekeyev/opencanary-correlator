"""Recoverable preparation and per-target, lease-fenced delivery.

Incident persistence creates a non-runnable preparation. Budget reservation and
publishing its targets are atomic; inline and background attempts subsequently
use exactly the same claim/transition path. A remote accept followed by a crash
can still duplicate a message: this is at-least-once, not exactly-once.
"""

from __future__ import annotations

import asyncio
import re
import time
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Final

from pydantic import ValidationError

from opencanary_correlator import metrics
from opencanary_correlator.audit import AuditLogger
from opencanary_correlator.config import Settings
from opencanary_correlator.connectors.base import BaseDispatcher, DispatchResult
from opencanary_correlator.core.delivery import deliver
from opencanary_correlator.core.incident import INCIDENT_TYPES, Incident
from opencanary_correlator.core.service_messages import ServiceKind, ServiceMessage
from opencanary_correlator.enrichment.models import Enrichment
from opencanary_correlator.incident_specs import INCIDENT_SPECS
from opencanary_correlator.storage.keys import (
    LEGACY_OUTBOX_INDEX,
    outbox_entry_id,
    outbox_envelope_key,
)
from opencanary_correlator.storage.redis_store import RedisStore

if TYPE_CHECKING:
    # Annotation-only: importing it at runtime creates a cycle, because
    # `enrichment.service` imports `core.service_messages`, which pulls in
    # `core.engine` -> `core.outbox` before this module has finished loading.
    # Any module that imported `enrichment` first then failed to import at all.
    from opencanary_correlator.enrichment.service import IncidentEnricher

BACKOFF_SECONDS: Final[tuple[float, ...]] = (1.0, 5.0, 30.0, 300.0, 1800.0)
_CLASSES_BY_PREFIX: Final[dict[str, type[Incident]]] = {
    spec.key_prefix: INCIDENT_TYPES[spec.name] for spec in INCIDENT_SPECS
}


def incident_class_for_key(key: str) -> type[Incident] | None:
    """Resolve the incident class from a persisted key."""
    for prefix, incident_cls in _CLASSES_BY_PREFIX.items():
        if key.startswith(prefix):
            return incident_cls
    return None


class AlertOutbox:
    """One state machine for immediate delivery and recovery workers."""

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
        self._dispatchers = {dispatcher.target_id: dispatcher for dispatcher in dispatchers}
        if len(self._dispatchers) != len(dispatchers):
            raise ValueError("duplicate delivery target identity")
        self._settings = settings
        self._audit = audit
        self._clock = clock
        self._task: asyncio.Task[None] | None = None
        self._enricher: IncidentEnricher | None = None

    def set_enricher(self, enricher: IncidentEnricher | None) -> None:
        """Use the existing bounded/cache-backed enricher during crash recovery."""
        self._enricher = enricher

    @property
    def channels(self) -> tuple[str, ...]:
        """Stable target IDs recorded by the incident repository."""
        return tuple(self._dispatchers)

    @property
    def _lease(self) -> float:
        # There is no sequential batch waiting behind this lease. The deadline
        # plus Redis command slack must fit even if the configured lease is tiny.
        return max(self._settings.outbox_lease, self._settings.dispatch_timeout + 10)

    async def prepare(self, incident: Incident) -> bool:
        """Make a preparation ready, or leave it recoverable if ownership is lost."""
        now = float(self._clock())
        token = await self._store.claim_alert(
            incident.key,
            now=now,
            lease=max(self._lease, self._settings.enrichment_timeout + 10),
            max_attempts=self._settings.outbox_max_attempts,
            preparing=True,
        )
        if not token:
            envelope = await self._store.hgetall(outbox_envelope_key(incident.key))
            return envelope.get("state") == "ready"
        if len(token) != 32:
            self._terminal(incident.key, token)
            return False
        # An incident may already carry context (an inline caller or a future
        # wiring that enriches before preparation). Re-running the provider would
        # overwrite it and spend another lookup; the snapshot below is all the
        # delivery needs.
        if self._enricher is not None and incident.enrichment is None:
            try:
                incident.enrichment = await asyncio.wait_for(
                    self._enricher.enrich(
                        incident.src_host,
                        occurred_at=datetime.fromtimestamp(float(incident.created), tz=UTC),
                    ),
                    timeout=self._settings.enrichment_timeout,
                )
            except Exception as exc:
                self._audit.emit(
                    "enrichment_failed",
                    "error",
                    {
                        "incident": incident.key,
                        "error_type": type(exc).__name__,
                    },
                )
        snapshot = self._snapshot(incident.enrichment)
        state = await self._store.prepare_alerts(
            incident.key,
            owner=token,
            now=float(self._clock()),
            enrichment=snapshot,
            budget_enabled=self._settings.alert_budget_enabled,
            node_id=incident.node_id,
            window=self._settings.alert_budget_window,
            per_node=self._settings.alert_budget_per_node,
            global_limit=self._settings.alert_budget_global,
        )
        if state:
            metrics.ALERTS_BUDGET.labels(
                result="allowed" if state == "ready" else "suppressed"
            ).inc()
        if state == "suppressed":
            self._audit.emit(
                "alert_suppressed",
                "warning",
                {
                    "incident": incident.key,
                    "node_id": incident.node_id,
                    "src_host": incident.src_host,
                },
            )
        return state == "ready"

    @staticmethod
    def _snapshot(enrichment: Enrichment | None) -> str:
        """Bounded provider-only context; never copy credentials or logdata."""
        if enrichment is None:
            return "null"
        geo = enrichment.geo
        if geo is not None:
            geo = geo.model_copy(
                update={
                    field: str(getattr(geo, field))[:256]
                    for field in ("country_code", "country", "city", "as_org")
                }
            )
        report = enrichment.virus_total
        if report is not None and report.checked is not None:
            report = report.model_copy(update={"checked": report.checked[:32]})
        return enrichment.model_copy(update={"geo": geo, "virus_total": report}).model_dump_json()

    async def deliver_inline(
        self, incident: Incident, dispatcher: BaseDispatcher
    ) -> DispatchResult | None:
        """Claim immediately before I/O, exactly as the background worker does."""
        return await self._attempt(outbox_entry_id(incident.key, dispatcher.target_id))

    @property
    def critical_tasks(self) -> tuple[asyncio.Task[None], ...]:
        """Background worker supervised by the runtime."""
        return (self._task,) if self._task is not None else ()

    async def start(self) -> None:
        if self._task is None:
            legacy = int(await self._store.client.zcard(LEGACY_OUTBOX_INDEX))
            if legacy:
                self._audit.emit("outbox_legacy_quarantined", "warning", {"pending": legacy})
            self._task = asyncio.create_task(self._loop(), name="alert-outbox")

    async def stop(self) -> None:
        task, self._task = self._task, None
        if task is not None:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    async def run_once(self) -> int:
        # Read candidate IDs without leasing the tail of the batch.
        preparing = await self._store.due_alerts(
            now=float(self._clock()),
            limit=self._settings.outbox_batch,
            preparing=True,
        )
        for incident_key in preparing:
            try:
                incident = await self._load(incident_key)
            except (ValueError, TypeError):
                incident = None
            if incident is None:
                await self._fail_preparation(incident_key, "incident_gone_or_corrupt")
            else:
                await self.prepare(incident)
        delivered = 0
        due = await self._store.due_alerts(
            now=float(self._clock()),
            limit=self._settings.outbox_batch,
        )
        for entry_id in due:
            result = await self._attempt(entry_id)
            delivered += int(result is not None and result.status == "success")
        pending, dead, oldest = await self._store.outbox_stats()
        metrics.OUTBOX_PENDING.set(pending)
        metrics.OUTBOX_DEAD_ENTRIES.set(dead)
        metrics.OUTBOX_OLDEST_PENDING.set(
            0.0 if oldest is None else max(0.0, float(self._clock()) - oldest)
        )
        return delivered

    async def _loop(self) -> None:
        while True:
            try:
                await self.run_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self._audit.emit("outbox_failed", "error", {"error_type": type(exc).__name__})
            await asyncio.sleep(self._settings.outbox_poll_interval)

    async def _send_notice(
        self, dispatcher: BaseDispatcher, notice: ServiceMessage
    ) -> DispatchResult | None:
        """One bounded attempt at a durable notice, audited per channel.

        The budget summary keeps the legacy `announce` rendering; every other
        notice goes through `notify`, which is the typed channel path.
        """
        try:
            if notice.kind is ServiceKind.BUDGET_SUMMARY and notice.lines:
                result = await asyncio.wait_for(
                    dispatcher.announce(notice.lines[0]),
                    timeout=self._settings.dispatch_timeout,
                )
            else:
                result = await asyncio.wait_for(
                    dispatcher.notify(notice),
                    timeout=self._settings.dispatch_timeout,
                )
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # a channel bug is a retry, not a crash
            self._audit.emit(
                "service_message_failed",
                "error",
                {
                    "kind": notice.kind.value,
                    "dispatcher": dispatcher.name,
                    "error_type": type(exc).__name__,
                },
            )
            return None
        self._audit.emit(
            "service_message_sent",
            "success" if result.status == "success" else "error",
            {"kind": notice.kind.value, "dispatcher": dispatcher.name},
        )
        return result

    async def _attempt(self, entry_id: str) -> DispatchResult | None:
        token = await self._store.claim_alert(
            entry_id,
            now=float(self._clock()),
            lease=self._lease,
            max_attempts=self._settings.outbox_max_attempts,
        )
        if not token:
            return None
        if len(token) != 32:
            self._terminal(entry_id, token)
            return None
        entry = await self._store.read_alert(entry_id)
        if entry is None:
            return None  # a deleted payload will be reclaimed as missing_entry
        dispatcher = self._dispatchers.get(entry.get("target", ""))
        if dispatcher is None:
            await self._finish(entry_id, token, "dead", "unknown_target")
            return None
        try:
            envelope = await self._store.hgetall(outbox_envelope_key(entry.get("incident", "")))
            notice = (
                ServiceMessage.model_validate_json(envelope["payload"])
                if envelope.get("kind") == "notice"
                else None
            )
            incident = None if notice is not None else await self._load(entry.get("incident", ""))
            if incident is not None and envelope.get("enrichment"):
                raw = envelope["enrichment"]
                incident.enrichment = None if raw == "null" else Enrichment.model_validate_json(raw)
        except (ValueError, TypeError, ValidationError):
            await self._finish(entry_id, token, "dead", "corrupt_payload")
            return None
        if incident is None and notice is None:
            await self._finish(entry_id, token, "dead", "incident_gone")
            return None
        if not await self._store.owns_alert(entry_id, owner=token, now=float(self._clock())):
            self._audit.emit(
                "alert_lease_lost", "warning", {"entry": entry_id, "transition": "send"}
            )
            return None
        if notice is not None:
            result = await self._send_notice(dispatcher, notice)
        elif incident is None:
            await self._finish(entry_id, token, "dead", "incident_gone")
            return None
        else:
            result = await deliver(
                dispatcher,
                incident,
                audit=self._audit,
                deadline=self._settings.dispatch_timeout,
                durable=True,
            )
        if result is not None and result.status == "success":
            if await self._finish(entry_id, token, "delivered"):
                metrics.OUTBOX_DELIVERED.labels(channel=dispatcher.name).inc()
            return result
        reason = "timeout_or_exception" if result is None else self._safe_reason(result)
        attempts = int(entry["attempts"])
        if attempts >= self._settings.outbox_max_attempts or (
            result is not None and not result.retryable
        ):
            await self._finish(entry_id, token, "dead", reason)
        else:
            delay = BACKOFF_SECONDS[min(attempts - 1, len(BACKOFF_SECONDS) - 1)]
            if result is not None and result.retry_after is not None:
                delay = max(delay, min(3600.0, result.retry_after))
            if await self._finish(entry_id, token, "ready", reason, delay=delay):
                metrics.OUTBOX_RETRIED.labels(channel=dispatcher.name).inc()
                self._audit.emit(
                    "alert_retry",
                    "warning",
                    {
                        "dispatcher": dispatcher.name,
                        "target": dispatcher.target_id,
                        "attempts": attempts,
                        "reason": reason,
                        "next_attempt_in": delay,
                    },
                )
        return result

    @staticmethod
    def _safe_reason(result: DispatchResult) -> str:
        # HTTP codes and internal classifier names only, never remote text/URLs.
        return (
            result.detail if re.fullmatch(r"[A-Za-z0-9_]{1,80}", result.detail) else result.status
        )

    async def _finish(
        self,
        entry_id: str,
        owner: str,
        state: str,
        reason: str = "",
        *,
        delay: float = 0,
    ) -> bool:
        now = float(self._clock())
        changed = await self._store.transition_alert(
            entry_id,
            owner=owner,
            now=now,
            state=state,
            error=reason,
            next_attempt=now + delay,
            retention=self._settings.outbox_delivery_retention,
        )
        if not changed:
            self._audit.emit(
                "alert_lease_lost", "warning", {"entry": entry_id, "transition": state}
            )
        elif state == "dead":
            self._terminal(entry_id, reason)
        return changed

    def _terminal(self, entry_id: str, reason: str) -> None:
        metrics.OUTBOX_TERMINAL.labels(
            reason=reason if re.fullmatch(r"[A-Za-z0-9_]{1,40}", reason) else "other"
        ).inc()
        metrics.OUTBOX_DEAD.labels(channel="unknown").inc()
        self._audit.emit("alert_dead_letter", "error", {"entry": entry_id, "reason": reason})

    async def _fail_preparation(self, incident_key: str, reason: str) -> None:
        token = await self._store.claim_alert(
            incident_key,
            now=float(self._clock()),
            lease=self._lease,
            max_attempts=self._settings.outbox_max_attempts,
            preparing=True,
        )
        if not token:
            return
        if len(token) == 32:
            if await self._store.fail_alert_preparation(
                incident_key, owner=token, now=float(self._clock()), reason=reason
            ):
                self._terminal(incident_key, reason)
        else:
            self._terminal(incident_key, token)

    async def _load(self, incident_key: str) -> Incident | None:
        cls = incident_class_for_key(incident_key)
        if cls is None:
            return None
        fields = await self._store.hgetall(incident_key)
        return cls.from_fields(incident_key, fields) if fields else None


__all__ = ["BACKOFF_SECONDS", "AlertOutbox", "incident_class_for_key"]
