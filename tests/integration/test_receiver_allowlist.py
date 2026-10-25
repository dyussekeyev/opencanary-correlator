"""Socket-level tests for the receiver source allowlist (OCC_RECEIVER_ALLOWED_IPS)."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest

from opencanary_correlator.connectors.receivers._allowlist import parse_allowed_networks
from opencanary_correlator.connectors.receivers.syslog import SyslogTCPReceiver, SyslogUDPReceiver
from opencanary_correlator.connectors.receivers.tcp_json import TCPJSONReceiver
from opencanary_correlator.constants import LogType

from .helpers import CollectingSink, audit_actions, wait_for_eof

pytestmark = pytest.mark.integration

LOOPBACK_ONLY = ["127.0.0.0/8"]
OTHER_NETWORK = ["10.0.0.0/8"]


def json_body() -> bytes:
    payload: dict[str, Any] = {
        "node_id": "canary-1",
        "src_host": "10.0.0.5",
        "src_port": 40000,
        "dst_host": "10.0.0.2",
        "dst_port": 21,
        "logtype": 2000,
        "logdata": {"USERNAME": "admin", "PASSWORD": "hunter2"},
    }
    return json.dumps(payload, sort_keys=True).encode()


async def make_tcp_json(sink: CollectingSink, audit: Any, allowed: list[str]) -> TCPJSONReceiver:
    receiver = TCPJSONReceiver(
        sink=sink,
        audit=audit,
        host="127.0.0.1",
        port=0,
        max_line_bytes=4096,
        partial_line_timeout=1.0,
        max_connections=10,
        allowed_networks=parse_allowed_networks(allowed),
    )
    await receiver.start()
    return receiver


async def make_udp_syslog(
    sink: CollectingSink, audit: Any, allowed: list[str]
) -> SyslogUDPReceiver:
    receiver = SyslogUDPReceiver(
        sink=sink,
        audit=audit,
        host="127.0.0.1",
        port=0,
        max_line_bytes=4096,
        allowed_networks=parse_allowed_networks(allowed),
    )
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


async def test_tcp_peer_outside_allowlist_is_disconnected(
    sink: CollectingSink, audit: Any, audit_stream: Any
) -> None:
    receiver = await make_tcp_json(sink, audit, OTHER_NETWORK)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", receiver.bound_port)
        assert await wait_for_eof(reader) == b""
        writer.close()
    finally:
        await receiver.stop()

    assert sink.events == []
    assert ("connection_rejected", "peer_not_allowed") in audit_actions(audit_stream)


async def test_tcp_peer_inside_allowlist_is_accepted(
    sink: CollectingSink, audit: Any, audit_stream: Any
) -> None:
    receiver = await make_tcp_json(sink, audit, LOOPBACK_ONLY)
    try:
        _reader, writer = await asyncio.open_connection("127.0.0.1", receiver.bound_port)
        writer.write(json_body() + b"\n")
        await writer.drain()
        events = await sink.wait_for(1)
        writer.close()
        await writer.wait_closed()
    finally:
        await receiver.stop()

    assert events[0].logtype is LogType.LOG_FTP_LOGIN_ATTEMPT
    assert ("connection_rejected", "peer_not_allowed") not in audit_actions(audit_stream)


async def test_udp_datagram_from_outside_allowlist_is_dropped(
    sink: CollectingSink, audit: Any, audit_stream: Any
) -> None:
    receiver = await make_udp_syslog(sink, audit, OTHER_NETWORK)
    try:
        await send_udp(receiver.bound_port, b"<134>canary-1 opencanary: " + json_body())
        await asyncio.sleep(0.2)
    finally:
        await receiver.stop()

    assert sink.events == []
    assert ("event_rejected", "peer_not_allowed") in audit_actions(audit_stream)


async def test_udp_datagram_inside_allowlist_is_accepted(sink: CollectingSink, audit: Any) -> None:
    receiver = await make_udp_syslog(sink, audit, LOOPBACK_ONLY)
    try:
        await send_udp(receiver.bound_port, b"<134>canary-1 opencanary: " + json_body())
        events = await sink.wait_for(1)
    finally:
        await receiver.stop()

    assert events[0].logtype is LogType.LOG_FTP_LOGIN_ATTEMPT


async def test_tcp_syslog_peer_outside_allowlist_is_disconnected(
    sink: CollectingSink, audit: Any, audit_stream: Any
) -> None:
    receiver = SyslogTCPReceiver(
        sink=sink,
        audit=audit,
        host="127.0.0.1",
        port=0,
        max_line_bytes=4096,
        partial_line_timeout=1.0,
        allowed_networks=parse_allowed_networks(OTHER_NETWORK),
    )
    await receiver.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", receiver.bound_port)
        assert await wait_for_eof(reader) == b""
        writer.close()
    finally:
        await receiver.stop()

    assert sink.events == []
    assert ("connection_rejected", "peer_not_allowed") in audit_actions(audit_stream)
