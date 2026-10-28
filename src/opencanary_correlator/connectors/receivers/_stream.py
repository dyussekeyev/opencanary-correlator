"""The per-connection stream protocol: framing loop, limits and timeouts.

It enforces the hardening rules the receivers rely on:

* a hard per-line byte limit (default 64 KiB);
* a timeout that only applies to a *stalled partial line*, so a silent
  keep-alive connection from `SocketJSONHandler` is never reaped;
* framing delegated to :mod:`._framing`, so the byte handling is testable
  without a socket.

The listening side lives in :mod:`._tcp`.
"""

from __future__ import annotations

import asyncio
import socket
from typing import TYPE_CHECKING, Final

from opencanary_correlator.connectors.receivers._framing import split_delimited

if TYPE_CHECKING:  # pragma: no cover - typing only, avoids an import cycle
    from opencanary_correlator.connectors.receivers._tcp import TCPStreamReceiver


CLOSE_REASON_LINE_TOO_LARGE: Final[str] = "line_too_large"
CLOSE_REASON_PARTIAL_LINE_TIMEOUT: Final[str] = "partial_line_timeout"
CLOSE_REASON_CONNECTION_LIMIT: Final[str] = "connection_limit"
CLOSE_REASON_RATE_LIMITED: Final[str] = "connection_rate_limited"
CLOSE_REASON_PEER_CLOSED: Final[str] = "peer_closed"


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
        """Release the timer and deregister the connection.

        The receiver is told whether *it* closed the connection or the peer did,
        because the two mean different things operationally: a peer closing
        `opencanaryd`'s keep-alive socket is how a canary goes silent, and a
        `SocketJSONHandler` does not always come back on its own.
        """
        self._cancel_timeout()
        closed_by_receiver = self._closed
        self._closed = True
        self._receiver.connection_lost(self, peer_closed=not closed_by_receiver)

    # --- Framing ------------------------------------------------------------

    def extract_payloads(self) -> tuple[list[bytes], bool]:
        """Split the buffer into complete payloads.

        Returns the payloads plus an ``overflow`` flag that tells the caller the
        peer exceeded the configured line limit. The framing itself lives in
        :mod:`._framing`, so a test can drive it without a socket.
        """
        return split_delimited(self._buffer, max_bytes=self._receiver.max_line_bytes)

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
