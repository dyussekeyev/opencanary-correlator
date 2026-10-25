"""Syslog receivers for OpenCanary's ``SyslogHandler`` output.

Two framings are accepted on TCP, as required by RFC 6587:

* **octet-counting** - ``MSG-LEN SP SYSLOG-MSG``;
* **non-transparent framing** - messages separated by ``\\n``/``\\r\\n``.

UDP carries one datagram per message. A message body that is a JSON object is
validated as a regular :class:`CanaryEvent`; any other body becomes a synthetic
``LOG_BASE_MSG`` event so a plain-text syslog sender still produces data.
Python's ``logging.handlers.SysLogHandler`` appends a NUL byte by default, which
is stripped here.
"""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from opencanary_correlator.audit import AuditLogger
from opencanary_correlator.connectors.base import EventSink, RateLimiter
from opencanary_correlator.connectors.receivers._allowlist import (
    PEER_NOT_ALLOWED,
    AllowedNetworks,
    is_peer_allowed,
)
from opencanary_correlator.connectors.receivers._base import NetworkReceiver
from opencanary_correlator.connectors.receivers._pipeline import (
    DEFAULT_CONCURRENCY,
    schema_error_details,
)
from opencanary_correlator.connectors.receivers._tcp import StreamProtocol, TCPStreamReceiver
from opencanary_correlator.constants import LogType
from opencanary_correlator.schemas import CanaryEvent

_PRI_RE = re.compile(r"^<(?P<pri>\d{1,3})>")
_RFC5424_RE = re.compile(
    r"^(?P<version>\d)\s+(?P<timestamp>\S+)\s+(?P<hostname>\S+)\s+(?P<app_name>\S+)\s+"
    r"(?P<procid>\S+)\s+(?P<msgid>\S+)\s*(?P<rest>.*)$",
    re.DOTALL,
)
_RFC3164_RE = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+"
    r"(?P<rest>.*)$",
    re.DOTALL,
)
_TAG_RE = re.compile(r"^(?P<tag>[A-Za-z0-9_.\-/]+)(?:\[\d+\])?:\s?")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_MAX_NODE_ID_LENGTH = 128


@dataclass(frozen=True, slots=True)
class SyslogMessage:
    """Parsed syslog envelope."""

    pri: int | None
    facility: int | None
    severity: int | None
    version: int | None
    timestamp: str | None
    hostname: str | None
    app_name: str | None
    message: str


def _clean_node_id(candidate: str | None) -> str:
    if not candidate:
        return "syslog"
    cleaned = _CONTROL_RE.sub("_", candidate)[:_MAX_NODE_ID_LENGTH]
    return cleaned or "syslog"


def _skip_structured_data(text: str) -> str:
    """Drop RFC 5424 structured-data blocks that precede the message."""
    while text.startswith("["):
        depth = 0
        in_quotes = False
        escaped = False
        consumed = 0
        for index, character in enumerate(text):
            if escaped:
                escaped = False
                continue
            if character == "\\":
                escaped = True
                continue
            if character == '"':
                in_quotes = not in_quotes
                continue
            if in_quotes:
                continue
            if character == "[":
                depth += 1
            elif character == "]":
                depth -= 1
                if depth == 0:
                    consumed = index + 1
                    break
        if consumed == 0:
            return ""
        text = text[consumed:].lstrip()
    return text


def parse_syslog(raw: bytes) -> SyslogMessage:
    """Parse a syslog envelope, raising :class:`ValueError` on a broken PRI."""
    text = raw.decode("utf-8", errors="replace").rstrip("\x00").strip("\r\n")
    if not text:
        raise ValueError("empty syslog message")

    pri: int | None = None
    match = _PRI_RE.match(text)
    if match is not None:
        pri = int(match.group("pri"))
        if pri > 191:
            raise ValueError(f"PRI out of range: {pri}")
        text = text[match.end() :]
    elif text.startswith("<"):
        raise ValueError("malformed PRI")

    facility = pri // 8 if pri is not None else None
    severity = pri % 8 if pri is not None else None

    version: int | None = None
    timestamp: str | None = None
    hostname: str | None = None
    app_name: str | None = None
    body = text

    rfc5424 = _RFC5424_RE.match(text)
    if rfc5424 is not None:
        version = int(rfc5424.group("version"))
        raw_timestamp = rfc5424.group("timestamp")
        timestamp = None if raw_timestamp == "-" else raw_timestamp
        hostname = rfc5424.group("hostname")
        app_name = rfc5424.group("app_name")
        remainder = rfc5424.group("rest").lstrip("\ufeff ")
        # RFC 5424 uses a lone "-" for absent structured data.
        if remainder == "-" or remainder.startswith("- "):
            remainder = remainder[1:].lstrip()
        body = _skip_structured_data(remainder)
    else:
        rfc3164 = _RFC3164_RE.match(text)
        if rfc3164 is not None:
            timestamp = rfc3164.group("timestamp")
            hostname = rfc3164.group("hostname")
            remainder = rfc3164.group("rest")
            tag = _TAG_RE.match(remainder)
            if tag is not None:
                app_name = tag.group("tag")
                remainder = remainder[tag.end() :]
            body = remainder.lstrip("\ufeff ")

    return SyslogMessage(
        pri=pri,
        facility=facility,
        severity=severity,
        version=version,
        timestamp=timestamp,
        hostname=hostname,
        app_name=app_name,
        message=body.strip(),
    )


def build_event(message: SyslogMessage, peer_ip: str) -> CanaryEvent:
    """Turn a parsed syslog message into a canary event.

    Raises :class:`pydantic.ValidationError` when a JSON body does not satisfy
    the event schema.
    """
    body = message.message.strip()
    node_id = _clean_node_id(message.hostname)

    # A JSON body may be the whole message or follow an unrecognised header
    # (``host app: {...}``). Only an explicitly JSON body is allowed to raise;
    # an embedded candidate that does not parse falls back to a text event.
    json_start = body.find("{")
    payload: Any = None
    if json_start == 0:
        payload = json.loads(body)
    elif json_start > 0:
        try:
            payload = json.loads(body[json_start:])
        except json.JSONDecodeError:
            payload = None
    if isinstance(payload, dict):
        payload.setdefault("node_id", node_id)
        payload.setdefault("src_host", peer_ip)
        payload.setdefault("logtype", int(LogType.LOG_BASE_MSG))
        payload.setdefault("logdata", {})
        if message.timestamp is not None:
            payload.setdefault("local_time", message.timestamp)
        return CanaryEvent.model_validate(payload)

    logdata: dict[str, Any] = {"message": body}
    if message.app_name:
        logdata["app_name"] = message.app_name
    if message.pri is not None:
        logdata["pri"] = message.pri
        logdata["facility"] = message.facility
        logdata["severity"] = message.severity

    payload = {
        "node_id": node_id,
        "src_host": peer_ip,
        "logtype": int(LogType.LOG_BASE_MSG),
        "logdata": logdata,
    }
    if message.timestamp is not None:
        payload["local_time"] = message.timestamp
    return CanaryEvent.model_validate(payload)


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
            payloads, overflow, octet_framing = self._extract_octet_counted()
            if octet_framing:
                return payloads, overflow
            self._octet_mode = False
        return super().extract_payloads()

    def _extract_octet_counted(self) -> tuple[list[bytes], bool, bool]:
        payloads: list[bytes] = []
        max_bytes = self._receiver.max_line_bytes
        while True:
            space = self._buffer.find(b" ")
            if space < 0:
                if not self._buffer:
                    return payloads, False, True
                if len(self._buffer) <= 10 and bytes(self._buffer).isdigit():
                    return payloads, False, True
                return payloads, False, False
            prefix = bytes(self._buffer[:space])
            if space > 10 or not prefix.isdigit():
                return payloads, False, False
            length = int(prefix)
            if length > max_bytes:
                return [], True, True
            start = space + 1
            if len(self._buffer) < start + length:
                return payloads, False, True
            payloads.append(bytes(self._buffer[start : start + length]))
            del self._buffer[: start + length]


def parse_syslog_frame(
    payload: bytes,
    peer_ip: str,
    audit_rejection: Callable[..., None],
) -> CanaryEvent | None:
    """Parse one syslog frame into an event, auditing and skipping any rejection.

    Shared by the TCP and UDP receivers so both reject the same inputs the same way.
    """
    try:
        message = parse_syslog(payload)
    except ValueError as exc:
        audit_rejection("malformed_syslog", peer_ip, error=str(exc))
        return None
    try:
        return build_event(message, peer_ip)
    except json.JSONDecodeError:
        audit_rejection("malformed_json", peer_ip)
        return None
    except ValidationError as exc:
        audit_rejection("schema_validation", peer_ip, **schema_error_details(exc))
        return None


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
        host: str = "0.0.0.0",  # noqa: S104 - receiver listens on every interface by default
        port: int = 0,
        max_line_bytes: int = 65536,
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
