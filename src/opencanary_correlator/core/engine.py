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

from opencanary_correlator import metrics
from opencanary_correlator.audit import AuditLogger
from opencanary_correlator.config import Settings
from opencanary_correlator.connectors.base import BaseDispatcher
from opencanary_correlator.constants import IGNORED_LOGTYPES
from opencanary_correlator.core.delivery import deliver
from opencanary_correlator.core.incident import Incident
from opencanary_correlator.core.outbox import AlertOutbox
from opencanary_correlator.core.rules import Rule
from opencanary_correlator.core.windows import DedupCache, event_fingerprint
from opencanary_correlator.enrichment.service import IncidentEnricher
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
        enricher: IncidentEnricher | None = None,
        outbox: AlertOutbox | None = None,
    ) -> None:
        self._rules = list(rules)
        self._dispatchers = list(dispatchers)
        self._dedup = dedup
        self._settings = settings
        self._audit = audit
        self._clock = clock
        self._enricher = enricher
        # Without an outbox the inline attempt is the whole story, as before.
        self._outbox = outbox

    @property
    def rule_names(self) -> tuple[str, ...]:
        """Names of the configured rules, for startup logging."""
        return tuple(rule.name for rule in self._rules)

    async def handle_event(self, event: CanaryEvent) -> None:
        """Correlate one validated event."""
        now = float(self._clock())
        fingerprint = event_fingerprint(event)
        token = await self._dedup.claim(fingerprint)
        if token is None:
            metrics.EVENTS_TOTAL.labels(result="deduplicated").inc()
            self._audit.emit(
                "event_deduplicated",
                "info",
                {"node_id": event.node_id, "logtype": int(event.logtype)},
            )
            return

        incidents: list[Incident] = []
        matched = False
        failed = False
        for rule in self._rules:
            if not rule.matches(event):
                continue
            matched = True
            try:
                incidents.extend(await rule.apply(event, now=now))
            except Exception as exc:
                failed = True
                metrics.RULE_FAILURES.labels(rule=rule.name).inc()
                self._audit.emit(
                    "rule_failed",
                    "error",
                    {
                        "rule": rule.name,
                        "node_id": event.node_id,
                        "error_type": type(exc).__name__,
                    },
                )

        if failed:
            # The claim was taken before the rules ran, so keeping it after a
            # failure would discard a redelivery of an event that never reached
            # the store: a second syslog relay, or a canary that reconnects.
            await self._dedup.release(fingerprint, token)
        else:
            await self._confirm_claim(fingerprint, token, event)

        if not matched:
            logtype = int(event.logtype)
            if logtype in IGNORED_LOGTYPES:
                # Node lifecycle records: expected, and nothing to correlate. An
                # INFO record keeps them traceable without filling the warning
                # stream an operator scans for real routing gaps.
                metrics.EVENTS_TOTAL.labels(result="ignored").inc()
                self._audit.emit(
                    "event_ignored",
                    "info",
                    {"node_id": event.node_id, "logtype": logtype},
                )
                return
            metrics.EVENTS_TOTAL.labels(result="unrouted").inc()
            self._audit.emit(
                "event_unrouted",
                "warning",
                {"node_id": event.node_id, "logtype": logtype},
            )
            return

        if incidents:
            await self._enrich(incidents)
            await self._dispatch(incidents)

    async def _confirm_claim(self, fingerprint: str, token: str, event: CanaryEvent) -> None:
        """Extend the dedup claim now that the event has been correlated.

        The claim was only a lease until this point, so a process that died in
        the middle suppressed nothing and the canary's redelivery still
        correlates. Losing the lease first means a rule ran longer than
        `OCC_DEDUP_LEASE`; the event is already stored, so a redelivery merges
        instead of notifying twice - but a rule that persistently outlives its
        lease is worth seeing.
        """
        if await self._dedup.confirm(fingerprint, token):
            return
        self._audit.emit(
            "event_dedup_lease_lost",
            "info",
            {"node_id": event.node_id, "logtype": int(event.logtype)},
        )

    async def _enrich(self, incidents: Sequence[Incident]) -> None:
        """Attach attacker context to the incidents that are about to be sent.

        Only newly created incidents reach this point (a merge inside the horizon
        does not notify), so the cost stays at one lookup per alert. `enrich`
        never waits longer than its own budget, and a failure here only means the
        alert goes out without context.
        """
        if self._enricher is None:
            return
        for incident in incidents:
            try:
                incident.enrichment = await self._enricher.enrich(incident.src_host)
            except Exception as exc:  # a broken enrichment must not lose the alert
                self._audit.emit(
                    "enrichment_failed",
                    "error",
                    {"incident": incident.key, "error_type": type(exc).__name__},
                )

    async def _dispatch(self, incidents: Sequence[Incident]) -> None:
        tasks = [
            self._deliver(dispatcher, incident)
            for dispatcher in self._dispatchers
            for incident in incidents
        ]
        if tasks:
            await asyncio.gather(*tasks)

    async def _deliver(self, dispatcher: BaseDispatcher, incident: Incident) -> None:
        """Try one channel now, then tell the outbox what happened.

        The attempt stays inline so a healthy deployment notifies immediately;
        the outbox only matters when it fails, which is when the entry it already
        holds is rescheduled instead of the alert being dropped on the floor.
        """
        result = await deliver(
            dispatcher,
            incident,
            audit=self._audit,
            deadline=float(self._settings.dispatch_timeout),
        )
        if self._outbox is None:
            return
        if result is None:
            error = "timeout"
        elif result.status != "success":
            error = result.status
        else:
            error = None
        await self._outbox.settle(incident.key, dispatcher.name, error=error)


__all__ = ["CorrelationEngine"]
