"""The correlation engine.

It is the only :class:`opencanary_correlator.connectors.base.EventSink` the
receivers need. For each event it deduplicates, applies every matching rule and
fans the resulting incidents out to the configured dispatchers, isolating
failures and timeouts so one broken channel cannot stall ingestion.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable, Sequence

from opencanary_correlator.audit import AuditLogger
from opencanary_correlator.config import Settings
from opencanary_correlator.connectors.base import BaseDispatcher
from opencanary_correlator.core.incident import Incident
from opencanary_correlator.core.rules import Rule
from opencanary_correlator.core.windows import DedupCache, event_fingerprint
from opencanary_correlator.schemas import CanaryEvent


class CorrelationEngine:
    """Stateless event correlator."""

    def __init__(
        self,
        *,
        rules: Sequence[Rule],
        dispatchers: Sequence[BaseDispatcher],
        dedup: DedupCache,
        settings: Settings,
        audit: AuditLogger,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._rules = list(rules)
        self._dispatchers = list(dispatchers)
        self._dedup = dedup
        self._settings = settings
        self._audit = audit
        self._clock = clock

    @property
    def rule_names(self) -> tuple[str, ...]:
        """Names of the configured rules, for startup logging."""
        return tuple(rule.name for rule in self._rules)

    async def handle_event(self, event: CanaryEvent) -> None:
        """Correlate one validated event."""
        now = float(self._clock())
        if not await self._dedup.first_seen(event_fingerprint(event)):
            self._audit.emit(
                "event_deduplicated",
                "info",
                {"node_id": event.node_id, "logtype": int(event.logtype)},
            )
            return

        incidents: list[Incident] = []
        matched = False
        for rule in self._rules:
            if not rule.matches(event):
                continue
            matched = True
            try:
                incidents.extend(await rule.apply(event, now=now))
            except Exception as exc:
                self._audit.emit(
                    "rule_failed",
                    "error",
                    {
                        "rule": rule.name,
                        "node_id": event.node_id,
                        "error_type": type(exc).__name__,
                    },
                )

        if not matched:
            self._audit.emit(
                "event_unrouted",
                "warning",
                {"node_id": event.node_id, "logtype": int(event.logtype)},
            )
            return

        if incidents:
            await self._dispatch(incidents)

    async def _dispatch(self, incidents: Sequence[Incident]) -> None:
        tasks = [
            self._deliver(dispatcher, incident)
            for dispatcher in self._dispatchers
            for incident in incidents
        ]
        if tasks:
            await asyncio.gather(*tasks)

    async def _deliver(self, dispatcher: BaseDispatcher, incident: Incident) -> None:
        started = time.perf_counter()
        try:
            result = await asyncio.wait_for(
                dispatcher.dispatch(incident),
                timeout=float(self._settings.dispatch_timeout),
            )
        except TimeoutError:
            self._audit.emit(
                "alert_dispatch",
                "error",
                {
                    "dispatcher": dispatcher.name,
                    "incident": incident.key,
                    "reason": "timeout",
                    "duration_ms": round((time.perf_counter() - started) * 1000, 1),
                },
            )
            return
        except Exception as exc:
            self._audit.emit(
                "alert_dispatch",
                "error",
                {
                    "dispatcher": dispatcher.name,
                    "incident": incident.key,
                    "error_type": type(exc).__name__,
                    "duration_ms": round((time.perf_counter() - started) * 1000, 1),
                },
            )
            return

        self._audit.emit(
            "alert_dispatch",
            "success" if result.status == "success" else "error",
            {
                "dispatcher": dispatcher.name,
                "incident": incident.key,
                "status": result.status,
                "duration_ms": round((time.perf_counter() - started) * 1000, 1),
            },
        )


__all__ = ["CorrelationEngine"]
