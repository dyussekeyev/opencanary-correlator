"""Common scaffolding shared by every network receiver.

Both the TCP stream receivers and the UDP datagram receivers own an
:class:`EventPipeline`, expose the same counters and bound port, and audit
rejected payloads the same way. Keeping that here means each transport only
implements its own socket lifecycle and framing.
"""

from __future__ import annotations

from abc import abstractmethod

from opencanary_correlator.audit import AuditLogger
from opencanary_correlator.connectors.base import BaseReceiver, EventSink, RateLimiter
from opencanary_correlator.connectors.receivers._allowlist import AllowedNetworks
from opencanary_correlator.connectors.receivers._pipeline import (
    DEFAULT_CONCURRENCY,
    EventPipeline,
    ReceiverStats,
)
from opencanary_correlator.schemas import CanaryEvent


class NetworkReceiver(BaseReceiver):
    """Base for receivers bound to a host/port and feeding an :class:`EventPipeline`."""

    def __init__(
        self,
        *,
        sink: EventSink,
        audit: AuditLogger,
        host: str,
        port: int,
        max_line_bytes: int,
        queue_size: int,
        rate_limiter: RateLimiter | None,
        concurrency: int,
        allowed_networks: AllowedNetworks,
    ) -> None:
        self.host = host
        self.port = port
        self.max_line_bytes = max_line_bytes
        self._audit = audit
        self._rate_limiter = rate_limiter
        self._allowed_networks = allowed_networks
        self._pipeline = EventPipeline(
            sink=sink,
            audit=audit,
            queue_size=queue_size,
            rate_limiter=rate_limiter,
            concurrency=concurrency,
        )
        self._bound_port: int | None = None

    @property
    def bound_port(self) -> int:
        """Actual listening port (useful when configured with ``port=0``)."""
        if self._bound_port is None:
            raise RuntimeError("receiver is not started")
        return self._bound_port

    @property
    def stats(self) -> ReceiverStats:
        """Counters for health reporting and tests."""
        return self._pipeline.stats

    @property
    def pending(self) -> int:
        """Events queued but not yet handed to the sink."""
        return self._pipeline.pending

    @abstractmethod
    def parse_payload(self, payload: bytes, peer_ip: str) -> CanaryEvent | None:
        """Turn one framed payload into an event, or reject it with an audit record."""

    def audit_rejection(self, reason: str, peer_ip: str, **details: object) -> None:
        """Record why a payload was rejected."""
        self._audit.emit(
            "event_rejected",
            "warning",
            {"receiver": self.name, "reason": reason, "peer": peer_ip, **details},
        )


__all__ = ["DEFAULT_CONCURRENCY", "NetworkReceiver"]
