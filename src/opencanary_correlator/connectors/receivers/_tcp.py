"""The listening side of a TCP receiver: sockets, connections and admission.

Both the JSON receiver and the syslog TCP receiver use this module. The
per-connection protocol lives in :mod:`._stream`; this module owns the server
socket, the connection cap, the optional distributed rate limiter and the
payload-to-event step.
"""

from __future__ import annotations

import asyncio
from abc import abstractmethod

from opencanary_correlator import metrics
from opencanary_correlator.audit import AuditLogger
from opencanary_correlator.connectors.base import EventSink, RateLimiter
from opencanary_correlator.connectors.receivers._allowlist import (
    PEER_NOT_ALLOWED,
    AllowedNetworks,
    is_peer_allowed,
)
from opencanary_correlator.connectors.receivers._base import NetworkReceiver
from opencanary_correlator.connectors.receivers._pipeline import DEFAULT_CONCURRENCY
from opencanary_correlator.connectors.receivers._stream import (
    CLOSE_REASON_CONNECTION_LIMIT,
    CLOSE_REASON_LINE_TOO_LARGE,
    CLOSE_REASON_PARTIAL_LINE_TIMEOUT,
    CLOSE_REASON_PEER_CLOSED,
    CLOSE_REASON_RATE_LIMITED,
    StreamProtocol,
)
from opencanary_correlator.schemas import CanaryEvent


class TCPStreamReceiver(NetworkReceiver):
    """Base class for line-oriented TCP receivers."""

    def __init__(
        self,
        *,
        sink: EventSink,
        audit: AuditLogger,
        host: str = "0.0.0.0",  # noqa: S104 - receiver listens on every interface by default
        port: int = 0,
        max_line_bytes: int = 65536,
        partial_line_timeout: float = 30.0,
        max_connections: int = 1000,
        queue_size: int = 10_000,
        rate_limiter: RateLimiter | None = None,
        concurrency: int = DEFAULT_CONCURRENCY,
        allowed_networks: AllowedNetworks = (),
    ) -> None:
        super().__init__(
            sink=sink,
            audit=audit,
            host=host,
            port=port,
            max_line_bytes=max_line_bytes,
            queue_size=queue_size,
            rate_limiter=rate_limiter,
            concurrency=concurrency,
            allowed_networks=allowed_networks,
        )
        self.partial_line_timeout = partial_line_timeout
        self.max_connections = max_connections
        self._server: asyncio.AbstractServer | None = None
        self._connections: set[StreamProtocol] = set()
        self._admission_tasks: set[asyncio.Task[None]] = set()

    # --- BaseReceiver -------------------------------------------------------

    @property
    def is_running(self) -> bool:
        """True while the server socket is bound."""
        return self._server is not None and self._server.is_serving()

    async def start(self) -> None:
        """Bind the listening socket and start the event consumer."""
        if self._server is not None:
            return
        loop = asyncio.get_running_loop()
        self._server = await loop.create_server(self._protocol_factory, self.host, self.port)
        sockets = self._server.sockets or ()
        if sockets:
            self._bound_port = int(sockets[0].getsockname()[1])
        await self._pipeline.start()
        self._audit.emit(
            "receiver_started",
            "info",
            {"receiver": self.name, "host": self.host, "port": self.bound_port},
        )

    async def stop(self) -> None:
        """Stop accepting connections, close peers and drain the pipeline."""
        server, self._server = self._server, None
        if server is not None:
            server.close()
            await server.wait_closed()
        for protocol in list(self._connections):
            protocol.close("shutdown")
        for task in list(self._admission_tasks):
            task.cancel()
        self._admission_tasks.clear()
        metrics.ACTIVE_CONNECTIONS.labels(receiver=self.name).set(0)
        await self._pipeline.stop()
        self._audit.emit(
            "receiver_stopped",
            "info",
            {"receiver": self.name, "accepted": self.stats.accepted},
        )

    # --- Connection handling ------------------------------------------------

    def connection_made(self, protocol: StreamProtocol) -> None:
        """Track the connection and enforce the allowlist and connection cap."""
        if not is_peer_allowed(protocol.peer_ip, self._allowed_networks):
            metrics.CONNECTION_REJECTIONS.labels(receiver=self.name, reason=PEER_NOT_ALLOWED).inc()
            self._audit.emit(
                "connection_rejected",
                "warning",
                {"receiver": self.name, "reason": PEER_NOT_ALLOWED, "peer": protocol.peer_ip},
            )
            protocol.close(PEER_NOT_ALLOWED)
            return
        self._connections.add(protocol)
        self._pipeline.stats.connections += 1
        metrics.ACTIVE_CONNECTIONS.labels(receiver=self.name).set(len(self._connections))
        if len(self._connections) > self.max_connections:
            metrics.CONNECTION_REJECTIONS.labels(
                receiver=self.name, reason=CLOSE_REASON_CONNECTION_LIMIT
            ).inc()
            self._audit.emit(
                "connection_rejected",
                "warning",
                {
                    "receiver": self.name,
                    "reason": CLOSE_REASON_CONNECTION_LIMIT,
                    "peer": protocol.peer_ip,
                    "active": len(self._connections),
                },
            )
            protocol.close(CLOSE_REASON_CONNECTION_LIMIT)
            return
        if self._rate_limiter is not None:
            task = asyncio.create_task(self._admit(protocol), name=f"{self.name}-admit")
            self._admission_tasks.add(task)
            task.add_done_callback(self._admission_tasks.discard)

    async def _admit(self, protocol: StreamProtocol) -> None:
        assert self._rate_limiter is not None  # noqa: S101 - guarded by the caller
        try:
            allowed = await self._rate_limiter.allow_connection(protocol.peer_ip)
        except Exception as exc:
            metrics.CONNECTION_REJECTIONS.labels(receiver=self.name, reason="limiter_error").inc()
            self._audit.emit(
                "connection_limiter_error",
                "error",
                {"receiver": self.name, "error_type": type(exc).__name__},
            )
            return
        if not allowed:
            metrics.CONNECTION_REJECTIONS.labels(
                receiver=self.name, reason=CLOSE_REASON_RATE_LIMITED
            ).inc()
            self._audit.emit(
                "connection_rejected",
                "warning",
                {
                    "receiver": self.name,
                    "reason": CLOSE_REASON_RATE_LIMITED,
                    "peer": protocol.peer_ip,
                },
            )
            protocol.close(CLOSE_REASON_RATE_LIMITED)

    def connection_lost(self, protocol: StreamProtocol, *, peer_closed: bool = False) -> None:
        """Forget a closed connection, and note who closed it.

        A peer-initiated close is audited at INFO: it is the moment a canary
        stopped delivering, and the correlator cannot ask it to reconnect. A
        close the receiver performed is already audited at WARNING by
        :meth:`connection_closed`.
        """
        self._connections.discard(protocol)
        metrics.ACTIVE_CONNECTIONS.labels(receiver=self.name).set(len(self._connections))
        if peer_closed:
            self._audit.emit(
                "connection_closed",
                "info",
                {
                    "receiver": self.name,
                    "reason": CLOSE_REASON_PEER_CLOSED,
                    "peer": protocol.peer_ip,
                },
            )

    def connection_closed(self, protocol: StreamProtocol, reason: str) -> None:
        """Audit a connection that the receiver itself terminated."""
        if reason == "shutdown":
            return
        self._audit.emit(
            "connection_closed",
            "warning",
            {"receiver": self.name, "reason": reason, "peer": protocol.peer_ip},
        )

    # --- Payload handling ---------------------------------------------------

    def payload_received(self, protocol: StreamProtocol, payload: bytes) -> None:
        """Parse one complete payload and queue the resulting event."""
        event = self.parse_payload(payload, protocol.peer_ip)
        if event is None:
            self._pipeline.record_rejection()
            return
        self._pipeline.submit(event)

    @abstractmethod
    def parse_payload(self, payload: bytes, peer_ip: str) -> CanaryEvent | None:
        """Turn one framed payload into an event, or reject it with an audit record."""

    @abstractmethod
    def _protocol_factory(self) -> StreamProtocol:
        """Build a protocol instance for a new connection."""


__all__ = [
    "CLOSE_REASON_CONNECTION_LIMIT",
    "CLOSE_REASON_LINE_TOO_LARGE",
    "CLOSE_REASON_PARTIAL_LINE_TIMEOUT",
    "CLOSE_REASON_PEER_CLOSED",
    "CLOSE_REASON_RATE_LIMITED",
    "StreamProtocol",
    "TCPStreamReceiver",
]
