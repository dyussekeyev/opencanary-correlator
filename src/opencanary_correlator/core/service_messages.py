"""Service messages: the correlator talking about itself.

An alert tells an operator that somebody attacked a canary. A service message
tells them that the *correlator* is degraded: a VirusTotal key was rejected, a
GeoIP database stopped answering, a channel's circuit breaker opened, no channel
delivered anything for the last few alerts, or the process started and stopped.

Three properties matter more than the wording:

* **No storm.** A rejected API key fails on every alert and a broken MMDB on
  every lookup. Each `(kind, subject)` gets one suppression slot per
  `OCC_SERVICE_COOLDOWN`; the message that gets through says how often the same
  thing happened while it was muted, and the rest are counted, not sent.
* **No hot-path cost.** Nothing here runs per event: the call sites are the
  failure paths that already emit an audit record, plus the dispatch result.
* **No secrets.** Messages are built from fixed templates, counts and status
  codes. Provider URLs, API keys and webhook paths never enter the text, and the
  subject used for deduplication is hashed before it becomes a Redis key.

Off by default: an existing deployment receives exactly what it did before until
`OCC_SERVICE_ENABLED=true` is set.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable, Iterable, Sequence
from enum import StrEnum
from typing import Final

from pydantic import BaseModel, ConfigDict

from opencanary_correlator.audit import AuditLogger
from opencanary_correlator.config import Settings
from opencanary_correlator.connectors.base import BaseDispatcher
from opencanary_correlator.storage.redis_store import RedisStore

logger = logging.getLogger(__name__)


class Severity(StrEnum):
    """How loudly a service message speaks."""

    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Ordering used by `OCC_SERVICE_MIN_SEVERITY`."""
        return _SEVERITY_RANK[self]


_SEVERITY_RANK: Final[dict[Severity, int]] = {
    Severity.INFO: 0,
    Severity.WARNING: 1,
    Severity.CRITICAL: 2,
}


class ServiceCategory(StrEnum):
    """Grouping an operator can switch off on its own."""

    ENRICHMENT = "enrichment"
    CHANNELS = "channels"
    LIFECYCLE = "lifecycle"


class ServiceKind(StrEnum):
    """Every message the correlator can produce about itself."""

    VIRUSTOTAL_KEY_REJECTED = "enrichment.virustotal.key_rejected"
    VIRUSTOTAL_QUOTA = "enrichment.virustotal.quota"
    VIRUSTOTAL_UNAVAILABLE = "enrichment.virustotal.unavailable"
    GEO_UNAVAILABLE = "enrichment.geo.unavailable"
    CHANNEL_CIRCUIT_OPEN = "channel.circuit_open"
    CHANNEL_ALL_FAILING = "channel.all_failing"
    LIFECYCLE_STARTED = "lifecycle.started"
    LIFECYCLE_STOPPED = "lifecycle.stopped"

    @property
    def category(self) -> ServiceCategory:
        """Which group the kind belongs to."""
        return _KIND_SPECS[self].category

    @property
    def severity(self) -> Severity:
        """How loudly the kind speaks by default."""
        return _KIND_SPECS[self].severity


class _KindSpec(BaseModel):
    """Static metadata of one kind: its group and its severity."""

    model_config = ConfigDict(frozen=True)

    category: ServiceCategory
    severity: Severity


_KIND_SPECS: Final[dict[ServiceKind, _KindSpec]] = {
    ServiceKind.VIRUSTOTAL_KEY_REJECTED: _KindSpec(
        category=ServiceCategory.ENRICHMENT, severity=Severity.CRITICAL
    ),
    ServiceKind.VIRUSTOTAL_QUOTA: _KindSpec(
        category=ServiceCategory.ENRICHMENT, severity=Severity.WARNING
    ),
    ServiceKind.VIRUSTOTAL_UNAVAILABLE: _KindSpec(
        category=ServiceCategory.ENRICHMENT, severity=Severity.WARNING
    ),
    ServiceKind.GEO_UNAVAILABLE: _KindSpec(
        category=ServiceCategory.ENRICHMENT, severity=Severity.WARNING
    ),
    ServiceKind.CHANNEL_CIRCUIT_OPEN: _KindSpec(
        category=ServiceCategory.CHANNELS, severity=Severity.WARNING
    ),
    ServiceKind.CHANNEL_ALL_FAILING: _KindSpec(
        category=ServiceCategory.CHANNELS, severity=Severity.CRITICAL
    ),
    ServiceKind.LIFECYCLE_STARTED: _KindSpec(
        category=ServiceCategory.LIFECYCLE, severity=Severity.INFO
    ),
    ServiceKind.LIFECYCLE_STOPPED: _KindSpec(
        category=ServiceCategory.LIFECYCLE, severity=Severity.INFO
    ),
}


class ServiceMessage(BaseModel):
    """One rendered-ready service message.

    `title` and `lines` are built from fixed templates by the caller, never from
    a provider response, so no URL, key or webhook path can reach a channel. The
    `subject` is what the suppression slot is keyed on and is not rendered: it
    may be a filesystem path or a node id from the wire.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: ServiceKind
    title: str
    lines: tuple[str, ...] = ()
    subject: str = ""
    #: Occurrences this message stands for, including the ones that were muted.
    count: int = 1

    @property
    def severity(self) -> Severity:
        """How loudly the message speaks, decided by its kind."""
        return self.kind.severity

    @property
    def category(self) -> ServiceCategory:
        """Which group the message belongs to."""
        return self.kind.category


def _parse_severity(value: str) -> Severity:
    """Read a configured severity, falling back to `warning` for anything odd.

    The setting is validated by pydantic before it reaches here; the fallback
    keeps a direct construction (a test, a plugin) from raising.
    """
    try:
        return Severity(value.strip().lower())
    except ValueError:
        return Severity.WARNING


class ServiceNotifier:
    """Filter, deduplicate, route and audit the correlator's own messages."""

    name: Final[str] = "service_messages"

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
        self._dispatchers = list(dispatchers)
        self._settings = settings
        self._audit = audit
        self._clock = clock
        self._categories = {value.strip().lower() for value in settings.service_categories}
        self._min_severity = _parse_severity(settings.service_min_severity)
        self._routed = self._route(settings.service_channels)

    # --- Wiring -------------------------------------------------------------

    def _route(self, configured: Iterable[str]) -> list[BaseDispatcher]:
        """Channels a service message goes to.

        Empty means every enabled channel: an operator who never names a channel
        wanted the message wherever the alerts go.
        """
        wanted = {name.strip().lower() for name in configured if name.strip()}
        if not wanted:
            return list(self._dispatchers)
        return [dispatcher for dispatcher in self._dispatchers if dispatcher.name in wanted]

    @property
    def enabled(self) -> bool:
        """True when the switch is on and something can receive a message."""
        return bool(self._settings.service_enabled and self._routed)

    @property
    def channels(self) -> tuple[str, ...]:
        """Names of the channels this notifier would use."""
        return tuple(dispatcher.name for dispatcher in self._routed)

    # --- Sending ------------------------------------------------------------

    async def notify(
        self,
        kind: ServiceKind,
        *,
        title: str,
        lines: Sequence[str] = (),
        subject: str = "",
        count: int = 1,
    ) -> bool:
        """Send one service message, returning True when any channel accepted it.

        The two filters run before the suppression slot is touched, so muting a
        kind an operator switched off cannot hide the next one that gets through.
        """
        if not self.enabled:
            return False
        if kind.category.value not in self._categories:
            return False
        if kind.severity.rank < self._min_severity.rank:
            return False

        admitted, repeats = await self._store.claim_service_message(
            kind=kind.value,
            subject=subject or kind.value,
            cooldown=float(self._settings.service_cooldown),
        )
        if not admitted:
            self._audit.emit(
                "service_message_suppressed",
                "info",
                {"kind": kind.value, "subject": subject, "count": 1},
            )
            return False

        message = ServiceMessage(
            kind=kind,
            title=title,
            lines=tuple(lines),
            subject=subject,
            count=max(count, repeats + 1),
        )
        results = await asyncio.gather(
            *(self._send_one(dispatcher, message) for dispatcher in self._routed)
        )
        return any(results)

    async def _send_one(self, dispatcher: BaseDispatcher, message: ServiceMessage) -> bool:
        """Deliver through one channel, bounded and never raising."""
        try:
            result = await asyncio.wait_for(
                dispatcher.notify(message),
                timeout=float(self._settings.dispatch_timeout),
            )
        except TimeoutError:
            self._audit.emit(
                "service_message_failed",
                "error",
                {"kind": message.kind.value, "dispatcher": dispatcher.name, "reason": "timeout"},
            )
            return False
        except NotImplementedError:
            self._audit.emit(
                "service_message_failed",
                "error",
                {
                    "kind": message.kind.value,
                    "dispatcher": dispatcher.name,
                    "reason": "not_supported",
                },
            )
            return False
        except Exception as exc:  # a channel bug must not kill the caller
            self._audit.emit(
                "service_message_failed",
                "error",
                {
                    "kind": message.kind.value,
                    "dispatcher": dispatcher.name,
                    "error_type": type(exc).__name__,
                },
            )
            return False

        self._audit.emit(
            "service_message_sent",
            "success" if result.status == "success" else "error",
            {
                "kind": message.kind.value,
                "dispatcher": dispatcher.name,
                "status": result.status,
                "count": message.count,
            },
        )
        return result.status == "success"


__all__ = [
    "ServiceCategory",
    "ServiceKind",
    "ServiceMessage",
    "ServiceNotifier",
    "Severity",
]
