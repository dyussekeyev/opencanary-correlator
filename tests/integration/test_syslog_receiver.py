"""Socket-level tests for the syslog receivers."""

from __future__ import annotations

import asyncio
import json
import logging
import logging.handlers
import socket
from typing import Any

import pytest

from opencanary_correlator.connectors.receivers.syslog import (
    SyslogTCPReceiver,
    SyslogUDPReceiver,
)
from opencanary_correlator.constants import LogType

from .helpers import CollectingSink, audit_actions, wait_for_eof

pytestmark = pytest.mark.integration


def octet_frame(message: bytes) -> bytes:
    """Wrap a syslog message in RFC 6587 octet-counting framing."""
    return str(len(message)).encode() + b" " + message


def json_body(**overrides: Any) -> bytes:
    payload: dict[str, Any] = {
        "node_id": "canary-1",
        "src_host": "10.0.0.5",
        "src_port": 40000,
        "dst_host": "10.0.0.2",
        "dst_port": 21,
        "logtype": 2000,
        "logdata": {"USERNAME": "admin", "PASSWORD": "hunter2"},
    }
    payload.update(overrides)
    return json.dumps(payload, sort_keys=True).encode()


async def make_tcp_receiver(
    sink: CollectingSink,
    audit: Any,
    **overrides: Any,
) -> SyslogTCPReceiver:
    params: dict[str, Any] = {
        "sink": sink,
        "audit": audit,
        "host": "127.0.0.1",
        "port": 0,
        "max_line_bytes": 4096,
        "partial_line_timeout": 1.0,
    }
    params.update(overrides)
    receiver = SyslogTCPReceiver(**params)
    await receiver.start()
    return receiver


async def make_udp_receiver(
    sink: CollectingSink,
    audit: Any,
    **overrides: Any,
) -> SyslogUDPReceiver:
    params: dict[str, Any] = {
        "sink": sink,
        "audit": audit,
        "host": "127.0.0.1",
        "port": 0,
        "max_line_bytes": 4096,
    }
    params.update(overrides)
    receiver = SyslogUDPReceiver(**params)
    await receiver.start()
    return receiver


async def send_udp(port: int, payload: bytes) -> None:
    loop = asyncio.get_running_loop()

    class _Sender(asyncio.DatagramProtocol):
        pass

    transport, _protocol = await loop.create_datagram_endpoint(
        _Sender, remote_addr=("127.0.0.1", port)
    )
    try:
        transport.sendto(payload)
    finally:
        transport.close()


# --- TCP framing ------------------------------------------------------------


async def test_octet_counted_json_frame_is_accepted(sink: Any, audit: Any) -> None:
    receiver = await make_tcp_receiver(sink, audit)
    try:
        _reader, writer = await asyncio.open_connection("127.0.0.1", receiver.bound_port)
        writer.write(octet_frame(b"<134>canary-1 opencanary: " + json_body()))
        await writer.drain()
        events = await sink.wait_for(1)
        writer.close()
        await writer.wait_closed()
    finally:
        await receiver.stop()

    assert events[0].logtype is LogType.LOG_FTP_LOGIN_ATTEMPT
    assert events[0].logdata["USERNAME"] == "admin"


async def test_octet_counted_frame_split_across_writes(sink: Any, audit: Any) -> None:
    receiver = await make_tcp_receiver(sink, audit)
    frame = octet_frame(b"<134>canary-1 opencanary: " + json_body())
    try:
        _reader, writer = await asyncio.open_connection("127.0.0.1", receiver.bound_port)
        writer.write(frame[:2])
        await writer.drain()
        await asyncio.sleep(0.05)
        writer.write(frame[2:12])
        await writer.drain()
        await asyncio.sleep(0.05)
        writer.write(frame[12:])
        await writer.drain()
        await sink.wait_for(1)
        writer.close()
        await writer.wait_closed()
    finally:
        await receiver.stop()

    assert len(sink.events) == 1


async def test_newline_framing_is_supported(sink: Any, audit: Any) -> None:
    receiver = await make_tcp_receiver(sink, audit)
    try:
        _reader, writer = await asyncio.open_connection("127.0.0.1", receiver.bound_port)
        writer.write(b"<134>Oct 24 10:00:00 canary-1 opencanary: " + json_body() + b"\n")
        await writer.drain()
        await sink.wait_for(1)
        writer.close()
        await writer.wait_closed()
    finally:
        await receiver.stop()

    assert sink.events[0].node_id == "canary-1"


def make_syslog_handler(port: int, socktype: socket.SocketKind) -> logging.handlers.SysLogHandler:
    """Build the same handler opencanaryd uses for syslog output."""
    handler = logging.handlers.SysLogHandler(
        address=("127.0.0.1", port),
        socktype=socktype,
    )
    handler.setFormatter(logging.Formatter("%(message)s"))
    return handler


async def test_python_syslog_handler_over_tcp_is_accepted(sink: Any, audit: Any) -> None:
    receiver = await make_tcp_receiver(sink, audit)
    handler = make_syslog_handler(receiver.bound_port, socket.SOCK_STREAM)
    logger = logging.getLogger("tests.opencanary.syslog.tcp")
    logger.handlers = [handler]
    logger.setLevel(logging.ERROR)
    logger.propagate = False
    try:
        logger.error(json_body().decode())
        events = await sink.wait_for(1)
    finally:
        logger.handlers = []
        handler.close()
        await receiver.stop()

    assert events[0].node_id == "canary-1"
    assert events[0].logtype is LogType.LOG_FTP_LOGIN_ATTEMPT


async def test_python_syslog_handler_over_udp_is_accepted(sink: Any, audit: Any) -> None:
    receiver = await make_udp_receiver(sink, audit)
    handler = make_syslog_handler(receiver.bound_port, socket.SOCK_DGRAM)
    logger = logging.getLogger("tests.opencanary.syslog.udp")
    logger.handlers = [handler]
    logger.setLevel(logging.ERROR)
    logger.propagate = False
    try:
        logger.error(json_body().decode())
        events = await sink.wait_for(1)
    finally:
        logger.handlers = []
        handler.close()
        await receiver.stop()

    assert events[0].node_id == "canary-1"
    assert events[0].logtype is LogType.LOG_FTP_LOGIN_ATTEMPT


async def test_plain_text_body_becomes_synthetic_event(sink: Any, audit: Any) -> None:
    receiver = await make_tcp_receiver(sink, audit)
    try:
        _reader, writer = await asyncio.open_connection("127.0.0.1", receiver.bound_port)
        writer.write(b"<134>Oct 24 10:00:00 canary-9 opencanary: failed login\x00\n")
        await writer.drain()
        events = await sink.wait_for(1)
        writer.close()
        await writer.wait_closed()
    finally:
        await receiver.stop()

    assert events[0].logtype is LogType.LOG_BASE_MSG
    assert events[0].node_id == "canary-9"
    assert events[0].logdata["message"] == "failed login"


async def test_malformed_pri_is_rejected_without_closing(
    sink: Any, audit: Any, audit_stream: Any
) -> None:
    receiver = await make_tcp_receiver(sink, audit)
    try:
        _reader, writer = await asyncio.open_connection("127.0.0.1", receiver.bound_port)
        writer.write(b"<abc>broken\n")
        await writer.drain()
        writer.write(b"<134>canary-1 opencanary: " + json_body() + b"\n")
        await writer.drain()
        await sink.wait_for(1)
        writer.close()
        await writer.wait_closed()
    finally:
        await receiver.stop()

    assert ("event_rejected", "malformed_syslog") in audit_actions(audit_stream)


async def test_oversized_octet_frame_closes_connection(
    sink: Any, audit: Any, audit_stream: Any
) -> None:
    receiver = await make_tcp_receiver(sink, audit, max_line_bytes=128)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", receiver.bound_port)
        writer.write(b"5000 " + b"x" * 5000)
        await writer.drain()
        assert await wait_for_eof(reader) == b""
        writer.close()
    finally:
        await receiver.stop()

    assert ("connection_closed", "line_too_large") in audit_actions(audit_stream)


# --- UDP --------------------------------------------------------------------


async def test_udp_json_message_is_accepted(sink: Any, audit: Any) -> None:
    receiver = await make_udp_receiver(sink, audit)
    try:
        await send_udp(receiver.bound_port, b"<134>canary-1 opencanary: " + json_body())
        events = await sink.wait_for(1)
    finally:
        await receiver.stop()

    assert events[0].src_port == 40000
    assert events[0].logtype is LogType.LOG_FTP_LOGIN_ATTEMPT


async def test_udp_plain_text_message_is_accepted(sink: Any, audit: Any) -> None:
    receiver = await make_udp_receiver(sink, audit)
    try:
        await send_udp(receiver.bound_port, b"<134>Oct 24 10:00:00 canary-2 app: hello")
        events = await sink.wait_for(1)
    finally:
        await receiver.stop()

    assert events[0].logtype is LogType.LOG_BASE_MSG
    assert events[0].logdata["message"] == "hello"


async def test_udp_oversized_datagram_is_rejected(sink: Any, audit: Any, audit_stream: Any) -> None:
    receiver = await make_udp_receiver(sink, audit, max_line_bytes=64)
    try:
        await send_udp(receiver.bound_port, b"x" * 200)
        await asyncio.sleep(0.2)
    finally:
        await receiver.stop()

    assert sink.events == []
    assert ("event_rejected", "datagram_too_large") in audit_actions(audit_stream)


async def test_udp_stop_is_idempotent(sink: Any, audit: Any) -> None:
    receiver = await make_udp_receiver(sink, audit)
    await receiver.stop()
    await receiver.stop()

    assert receiver.is_running is False
