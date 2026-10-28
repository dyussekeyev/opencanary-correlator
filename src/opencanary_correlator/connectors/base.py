"""Connector contracts shared by receivers, dispatchers and the core engine.

The core must not import concrete connectors; it talks to :class:`EventSink`
(input) and :class:`BaseDispatcher` (output) only. Concrete receivers live in
``connectors/receivers`` and concrete dispatchers in ``connectors/dispatchers``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, ClassVar, Literal, Protocol

from pydantic import BaseModel, ConfigDict

from opencanary_correlator.schemas import CanaryEvent

if TYPE_CHECKING:  # pragma: no cover - typing only
    from opencanary_correlator.enrichment.models import Enrichment


class EventSink(Protocol):
    """Consumer of validated canary events."""

    async def handle_event(self, event: CanaryEvent) -> None:
        """Process one validated event."""
        ...


class RateLimiter(Protocol):
    """Distributed limiter used by receivers before accepting work."""

    async def allow_connection(self, source_ip: str) -> bool:
        """Return False when a new connection from `source_ip` must be refused."""
        ...

    async def allow_event(self, node_id: str) -> bool:
        """Return False when events from `node_id` exceed the configured rate."""
        ...


class AllowAllRateLimiter:
    """No-op limiter used when rate limiting is disabled."""

    async def allow_connection(self, source_ip: str) -> bool:
        """Always allow the connection."""
        return True

    async def allow_event(self, node_id: str) -> bool:
        """Always allow the event."""
        return True


class IncidentLike(Protocol):
    """What dispatchers need from a correlated incident.

    The scalar fields feed the rich alert layout (see
    ``connectors.dispatchers.alert_text``); the ``format_*`` methods render the
    legacy reports that ``minimal`` detail level still sends.
    """

    key: str
    node_id: str
    src_host: str
    src_port: int
    dst_host: str
    dst_port: int
    created: int
    events_count: int
    logdata: str | None
    description: str
    #: Attacker-IP context attached by the engine before dispatch. Optional: a
    #: deployment without enrichment, or a plugin's own incident object, simply
    #: leaves it None and the alert renders without those rows.
    enrichment: Enrichment | None

    @property
    def display_description(self) -> str:
        """Incident name to show in an alert."""
        ...

    def format_title(self) -> str:
        """Short one-line title."""
        ...

    def format_report(self) -> str:
        """Full plain-text report."""
        ...

    def format_report_short(self) -> str:
        """Compact report for SMS/Telegram-sized channels."""
        ...


class DispatchResult(BaseModel):
    """Outcome of delivering one incident to one channel."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    dispatcher: str
    status: Literal["success", "error", "skipped"]
    detail: str = ""
    duration_ms: float | None = None


class BaseReceiver(ABC):
    """A source of canary events."""

    name: ClassVar[str] = "receiver"

    @property
    @abstractmethod
    def is_running(self) -> bool:
        """True while the receiver is bound and accepting input."""

    @abstractmethod
    async def start(self) -> None:
        """Bind sockets and start background tasks."""

    @abstractmethod
    async def stop(self) -> None:
        """Stop accepting input and release resources."""


class BaseDispatcher(ABC):
    """An alert delivery channel."""

    name: ClassVar[str] = "dispatcher"

    @abstractmethod
    async def dispatch(self, incident: IncidentLike) -> DispatchResult:
        """Deliver an incident, returning the outcome instead of raising."""

    async def aclose(self) -> None:  # noqa: B027 - optional hook, not every channel owns resources
        """Release network resources. Dispatchers without state need not override."""


class ConnectorRegistry:
    """Name-to-class registry used by the CLI to build connectors from config."""

    def __init__(self) -> None:
        self._receivers: dict[str, type[BaseReceiver]] = {}
        self._dispatchers: dict[str, type[BaseDispatcher]] = {}

    def register_receiver(self, receiver_cls: type[BaseReceiver]) -> type[BaseReceiver]:
        """Register a receiver class under its `name`."""
        self._receivers[receiver_cls.name] = receiver_cls
        return receiver_cls

    def register_dispatcher(self, dispatcher_cls: type[BaseDispatcher]) -> type[BaseDispatcher]:
        """Register a dispatcher class under its `name`."""
        self._dispatchers[dispatcher_cls.name] = dispatcher_cls
        return dispatcher_cls

    def receiver(self, name: str) -> type[BaseReceiver]:
        """Look up a receiver class."""
        try:
            return self._receivers[name]
        except KeyError as exc:
            raise KeyError(f"unknown receiver: {name}") from exc

    def dispatcher(self, name: str) -> type[BaseDispatcher]:
        """Look up a dispatcher class."""
        try:
            return self._dispatchers[name]
        except KeyError as exc:
            raise KeyError(f"unknown dispatcher: {name}") from exc

    @property
    def receiver_names(self) -> frozenset[str]:
        """Names of all registered receivers."""
        return frozenset(self._receivers)

    @property
    def dispatcher_names(self) -> frozenset[str]:
        """Names of all registered dispatchers."""
        return frozenset(self._dispatchers)


__all__ = [
    "AllowAllRateLimiter",
    "BaseDispatcher",
    "BaseReceiver",
    "ConnectorRegistry",
    "DispatchResult",
    "EventSink",
    "IncidentLike",
    "RateLimiter",
]
