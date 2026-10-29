"""Syslog receivers for OpenCanary's ``SyslogHandler`` output.

Two framings are accepted on TCP, as required by RFC 6587:

* **octet-counting** - ``MSG-LEN SP SYSLOG-MSG``;
* **non-transparent framing** - messages separated by ``\\n``/``\\r\\n``.

UDP carries one datagram per message. A message body that is a JSON object is
validated as a regular :class:`CanaryEvent`; any other body becomes a synthetic
``LOG_BASE_MSG`` event so a plain-text syslog sender still produces data.
Python's ``logging.handlers.SysLogHandler`` appends a NUL byte by default, which
is stripped here.

The codec (envelope parsing and event construction) lives in
:mod:`opencanary_correlator.connectors.receivers._syslog_codec`, and the framing
in :mod:`opencanary_correlator.connectors.receivers._framing`; this module is
the transport. The parsed types are re-exported, so importing them from here
keeps working.
"""

from __future__ import annotations

import asyncio
from typing import Any

from opencanary_correlator.audit import AuditLogger
from opencanary_correlator.connectors.base import EventSink, RateLimiter
from opencanary_correlator.connectors.receivers._allowlist import (
    PEER_NOT_ALLOWED,
    AllowedNetworks,
    is_peer_allowed,
)
from opencanary_correlator.connectors.receivers._base import NetworkReceiver
from opencanary_correlator.connectors.receivers._framing import split_octet_counted
from opencanary_correlator.connectors.receivers._pipeline import DEFAULT_CONCURRENCY
from opencanary_correlator.connectors.receivers._syslog_codec import (
    SyslogMessage,
    build_event,
    parse_syslog,
    parse_syslog_frame,
)
from opencanary_correlator.connectors.receivers._tcp import StreamProtocol, TCPStreamReceiver
from opencanary_correlator.presence import NodeRegistry
from opencanary_correlator.schemas import CanaryEvent


class SyslogTCPProtocol(StreamProtocol):
    """RFC 6587 TCP framing: octet-counting with a newline fallback."""

    def __init__(self, receiver: TCPStreamReceiver) -> None:
        super().__init__(receiver)
        self._octet_mode: bool | None = None

    def extract_payloads(self) -> tuple[list[bytes], bool]:
        """Extract complete syslog frames, auto-detecting the framing mode."""
        if self._octet_mode is None:
            if not self._buffer:
                return [], False
            self._octet_mode = bytes(self._buffer[:1]).isdigit()
        if self._octet_mode:
            payloads, overflow, octet_framing = split_octet_counted(
                self._buffer, max_bytes=self._receiver.max_line_bytes
            )
            if octet_framing:
                return payloads, overflow
            self._octet_mode = False
        return super().extract_payloads()


class SyslogTCPReceiver(TCPStreamReceiver):
    """Receive syslog over TCP (octet-counting or newline framing)."""

    name = "syslog_tcp"

    def _protocol_factory(self) -> StreamProtocol:
        return SyslogTCPProtocol(self)

    def parse_payload(self, payload: bytes, peer_ip: str) -> CanaryEvent | None:
        """Parse a syslog frame and validate any embedded canary JSON."""
        return parse_syslog_frame(payload, peer_ip, self.audit_rejection)


class SyslogDatagramProtocol(asyncio.DatagramProtocol):
    """Datagram endpoint forwarding payloads to the UDP receiver."""

    def __init__(self, receiver: SyslogUDPReceiver) -> None:
        self._receiver = receiver

    def datagram_received(self, data: bytes, addr: Any) -> None:
        """Handle one datagram."""
        peer_ip = str(addr[0]) if isinstance(addr, tuple) and addr else ""
        self._receiver.datagram_received(data, peer_ip)

    def error_received(self, exc: Exception) -> None:
        """Audit a datagram-level error instead of raising."""
        self._receiver.audit_error(exc)


class SyslogUDPReceiver(NetworkReceiver):
    """Receive syslog over UDP, one message per datagram."""

    name = "syslog_udp"

    def __init__(
        self,
        *,
        sink: EventSink,
        audit: AuditLogger,
        # Loopback, like the TCP receivers: UDP has no connection to admit, so an
        # exposed datagram port accepts forged events from any peer.
        host: str = "127.0.0.1",
        port: int = 0,
        max_line_bytes: int = 65536,
        queue_size: int = 10_000,
        rate_limiter: RateLimiter | None = None,
        concurrency: int = DEFAULT_CONCURRENCY,
        allowed_networks: AllowedNetworks = (),
        nodes: NodeRegistry | None = None,
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
            nodes=nodes,
        )
        self._transport: asyncio.DatagramTransport | None = None

    @property
    def is_running(self) -> bool:
        """True while the datagram endpoint is open."""
        return self._transport is not None

    async def start(self) -> None:
        """Bind the UDP socket and start the event consumer."""
        if self._transport is not None:
            return
        loop = asyncio.get_running_loop()
        transport, _protocol = await loop.create_datagram_endpoint(
            lambda: SyslogDatagramProtocol(self),
            local_addr=(self.host, self.port),
        )
        # Do not isinstance-check the transport: the POSIX selector transport
        # implements the datagram API without inheriting DatagramTransport
        # (only the Windows one does), so a runtime check would reject it.
        self._transport = transport
        sockname = transport.get_extra_info("sockname")
        if isinstance(sockname, tuple) and len(sockname) >= 2:
            self._bound_port = int(sockname[1])
        await self._pipeline.start()
        self._audit.emit(
            "receiver_started",
            "info",
            {"receiver": self.name, "host": self.host, "port": self.bound_port},
        )

    async def stop(self) -> None:
        """Close the socket and drain the pipeline."""
        transport, self._transport = self._transport, None
        if transport is not None:
            transport.close()
        await self._pipeline.stop()
        self._audit.emit("receiver_stopped", "info", {"receiver": self.name})

    def datagram_received(self, data: bytes, peer_ip: str) -> None:
        """Validate one datagram and queue the resulting event."""
        if not is_peer_allowed(peer_ip, self._allowed_networks):
            self.audit_rejection(PEER_NOT_ALLOWED, peer_ip)
            self._pipeline.record_rejection()
            return
        if len(data) > self.max_line_bytes:
            self.audit_rejection("datagram_too_large", peer_ip, size=len(data))
            self._pipeline.record_rejection()
            return
        for line in data.splitlines() or [data]:
            if not line.strip():
                continue
            event = self.parse_payload(line, peer_ip)
            if event is None:
                self._pipeline.record_rejection()
                continue
            self._pipeline.submit(event)

    def parse_payload(self, payload: bytes, peer_ip: str) -> CanaryEvent | None:
        """Parse one syslog line from a datagram."""
        return parse_syslog_frame(payload, peer_ip, self.audit_rejection)

    def audit_error(self, exc: Exception) -> None:
        """Record a datagram-level error."""
        self._audit.emit(
            "datagram_error",
            "error",
            {"receiver": self.name, "error_type": type(exc).__name__},
        )


__all__ = [
    "SyslogDatagramProtocol",
    "SyslogMessage",
    "SyslogTCPProtocol",
    "SyslogTCPReceiver",
    "SyslogUDPReceiver",
    "build_event",
    "parse_syslog",
]
