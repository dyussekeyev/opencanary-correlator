"""Shared asyncio TCP receiver plumbing.

Both the JSON receiver and the syslog TCP receiver use this module. It enforces
the hardening rules from ``docs/internal/EXECPLAN-refactor.md``:

* a hard per-line byte limit (default 64 KiB);
* a timeout that only applies to a *stalled partial line*, so a silent
  keep-alive connection from `SocketJSONHandler` is never reaped;
* a connection cap and an optional distributed admission/rate limiter;
* all payload handling through the bounded :class:`EventPipeline`.
"""

from __future__ import annotations

import asyncio
import socket
from abc import abstractmethod
from typing import Final

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
from opencanary_correlator.schemas import CanaryEvent

CLOSE_REASON_LINE_TOO_LARGE: Final[str] = "line_too_large"
CLOSE_REASON_PARTIAL_LINE_TIMEOUT: Final[str] = "partial_line_timeout"
CLOSE_REASON_CONNECTION_LIMIT: Final[str] = "connection_limit"
CLOSE_REASON_RATE_LIMITED: Final[str] = "connection_rate_limited"


class StreamProtocol(asyncio.Protocol):
    """Newline-delimited TCP protocol with partial-line timeout and size limits."""

    def __init__(self, receiver: TCPStreamReceiver) -> None:
        self._receiver = receiver
        self._buffer = bytearray()
        self._transport: asyncio.BaseTransport | None = None
        self._timeout_handle: asyncio.TimerHandle | None = None
        self._closed = False
        self.peer_ip: str = ""

    # --- asyncio.Protocol ---------------------------------------------------

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        """Record the transport, tune the socket and register the connection."""
        self._transport = transport
        extra_socket = transport.get_extra_info("socket")
        if isinstance(extra_socket, socket.socket):
            extra_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            extra_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        peername = transport.get_extra_info("peername")
        if isinstance(peername, tuple) and peername:
            self.peer_ip = str(peername[0])
        self._receiver.connection_made(self)

    def data_received(self, data: bytes) -> None:
        """Buffer incoming bytes, extract complete frames and dispatch them."""
        if self._closed:
            return
        self._buffer.extend(data)
        payloads, overflow = self.extract_payloads()
        for payload in payloads:
            self._receiver.payload_received(self, payload)
        if overflow:
            self.close(CLOSE_REASON_LINE_TOO_LARGE)
            return
        self._arm_timeout()

    def connection_lost(self, exc: Exception | None) -> None:
        """Release the timer and deregister the connection."""
        self._cancel_timeout()
        self._closed = True
        self._receiver.connection_lost(self)

    # --- Framing ------------------------------------------------------------

    def extract_payloads(self) -> tuple[list[bytes], bool]:
        """Split the buffer into complete payloads.

        Returns the payloads plus an ``overflow`` flag that tells the caller the
        peer exceeded the configured line limit.
        """
        max_bytes = self._receiver.max_line_bytes
        payloads: list[bytes] = []
        while True:
            index = self._next_delimiter()
            if index < 0:
                break
            line = bytes(self._buffer[:index]).rstrip(b"\r")
            del self._buffer[: index + 1]
            if len(line) > max_bytes:
                return [], True
            payloads.append(line)
        if len(self._buffer) > max_bytes:
            return [], True
        return payloads, False

    def _next_delimiter(self) -> int:
        """Return the offset of the first frame delimiter, or -1.

        Newline-separated frames are the OpenCanary ``SocketJSONHandler``
        format. NUL is also accepted because Python's ``SysLogHandler``
        terminates TCP messages with ``\\x00`` instead of a newline.
        """
        newline = self._buffer.find(b"\n")
        nul = self._buffer.find(b"\x00")
        if newline < 0:
            return nul
        if nul < 0:
            return newline
        return min(newline, nul)

    # --- Lifecycle ----------------------------------------------------------

    def close(self, reason: str) -> None:
        """Close the connection and audit why."""
        if self._closed:
            return
        self._closed = True
        self._cancel_timeout()
        self._receiver.connection_closed(self, reason)
        if self._transport is not None:
            self._transport.close()

    def _arm_timeout(self) -> None:
        self._cancel_timeout()
        if not self._buffer or self._closed:
            return
        loop = asyncio.get_running_loop()
        self._timeout_handle = loop.call_later(
            self._receiver.partial_line_timeout, self._on_timeout
        )

    def _cancel_timeout(self) -> None:
        if self._timeout_handle is not None:
            self._timeout_handle.cancel()
            self._timeout_handle = None

    def _on_timeout(self) -> None:
        self._timeout_handle = None
        self.close(CLOSE_REASON_PARTIAL_LINE_TIMEOUT)


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

    def connection_lost(self, protocol: StreamProtocol) -> None:
        """Forget a closed connection."""
        self._connections.discard(protocol)
        metrics.ACTIVE_CONNECTIONS.labels(receiver=self.name).set(len(self._connections))

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
    "CLOSE_REASON_RATE_LIMITED",
    "StreamProtocol",
    "TCPStreamReceiver",
]
