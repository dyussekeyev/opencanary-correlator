"""Socket-level tests for the SocketJSONHandler-compatible TCP receiver."""

from __future__ import annotations

import asyncio
import json
import logging
import logging.handlers
from typing import Any

import pytest
from helpers import CollectingSink, audit_actions, wait_for_eof

from opencanary_correlator.connectors.receivers.tcp_json import TCPJSONReceiver
from opencanary_correlator.constants import LogType

pytestmark = pytest.mark.integration


class SocketJSONHandler(logging.handlers.SocketHandler):
    """Byte-for-byte copy of `opencanary.logger.SocketJSONHandler` framing."""

    def makePickle(self, record: logging.LogRecord) -> bytes:  # noqa: N802 - stdlib API
        return record.getMessage().encode("utf-8") + b"\n"


async def make_receiver(
    sink: CollectingSink,
    audit: Any,
    **overrides: Any,
) -> TCPJSONReceiver:
    params: dict[str, Any] = {
        "sink": sink,
        "audit": audit,
        "host": "127.0.0.1",
        "port": 0,
        "max_line_bytes": 4096,
        "partial_line_timeout": 1.0,
        "max_connections": 10,
    }
    params.update(overrides)
    receiver = TCPJSONReceiver(**params)
    await receiver.start()
    return receiver


async def open_connection(
    receiver: TCPJSONReceiver,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    return await asyncio.open_connection("127.0.0.1", receiver.bound_port)


async def send(writer: asyncio.StreamWriter, payload: bytes) -> None:
    writer.write(payload)
    await writer.drain()


# --- Compatibility ----------------------------------------------------------


async def test_accepts_payload_from_socket_json_handler(sink, audit, event_factory) -> None:
    receiver = await make_receiver(sink, audit)
    handler = SocketJSONHandler("127.0.0.1", receiver.bound_port)
    logger = logging.getLogger("tests.opencanary.socket")
    logger.handlers = [handler]
    logger.setLevel(logging.WARNING)
    logger.propagate = False
    try:
        logger.warning(json.dumps(event_factory(), sort_keys=True))
        events = await sink.wait_for(1)
    finally:
        logger.handlers = []
        handler.close()
        await receiver.stop()

    event = events[0]
    assert event.node_id == "canary-1"
    assert event.src_host == "10.0.0.5"
    assert event.src_port == 4444
    assert event.logtype is LogType.LOG_FTP_LOGIN_ATTEMPT
    assert event.logdata == {"USERNAME": "admin", "PASSWORD": "hunter2"}


async def test_accepts_unknown_logtypes_and_empty_hosts(sink, audit) -> None:
    receiver = await make_receiver(sink, audit)
    try:
        _reader, writer = await open_connection(receiver)
        payload = {"node_id": "new-canary", "logtype": 77777, "src_host": "", "src_port": -1}
        await send(writer, (json.dumps(payload) + "\n").encode())
        events = await sink.wait_for(1)
        writer.close()
        await writer.wait_closed()
    finally:
        await receiver.stop()

    assert int(events[0].logtype) == 77777
    assert events[0].src_host == ""
    assert events[0].src_port == -1


async def test_handles_batched_split_and_crlf_lines(sink, audit, event_factory) -> None:
    receiver = await make_receiver(sink, audit)
    first = json.dumps(event_factory(src_port=1001), sort_keys=True).encode()
    second = json.dumps(event_factory(src_port=1002), sort_keys=True).encode()
    third = json.dumps(event_factory(src_port=1003), sort_keys=True).encode()
    try:
        _reader, writer = await open_connection(receiver)
        await send(writer, first + b"\r\n\n" + second + b"\n")
        await send(writer, third[:20])
        await asyncio.sleep(0.05)
        await send(writer, third[20:] + b"\n")
        events = await sink.wait_for(3)
        writer.close()
        await writer.wait_closed()
    finally:
        await receiver.stop()

    assert sorted(event.src_port for event in events) == [1001, 1002, 1003]


# --- Rejections that must not kill the connection ---------------------------


async def test_canary_error_line_and_bad_payloads_do_not_close_connection(
    sink, audit, audit_stream, event_factory
) -> None:
    receiver = await make_receiver(sink, audit)
    try:
        _reader, writer = await open_connection(receiver)
        await send(writer, b'[ERR] \'{"node_id": "x"}\'\n')
        await send(writer, b"not-json\n")
        await send(writer, b'{"node_id": ""}\n')
        await send(writer, b'["array", "payload"]\n')
        await send(writer, b"\xff\xfe\n")
        await send(writer, (json.dumps(event_factory(), sort_keys=True) + "\n").encode())
        events = await sink.wait_for(1)
        writer.close()
        await writer.wait_closed()
    finally:
        await receiver.stop()

    assert len(events) == 1
    reasons = [reason for _action, reason in audit_actions(audit_stream)]
    assert "canary_error_line" in reasons
    assert "malformed_json" in reasons
    assert "schema_validation" in reasons
    assert "non_object_payload" in reasons
    assert "invalid_utf8" in reasons


# --- Hardening --------------------------------------------------------------


async def test_oversized_line_closes_connection(sink, audit, audit_stream) -> None:
    receiver = await make_receiver(sink, audit, max_line_bytes=256)
    try:
        reader, writer = await open_connection(receiver)
        await send(writer, b'{"node_id": "' + b"x" * 400)
        remaining = await wait_for_eof(reader)
        writer.close()
    finally:
        await receiver.stop()

    assert remaining == b""
    assert ("connection_closed", "line_too_large") in audit_actions(audit_stream)
    assert sink.events == []


async def test_partial_line_timeout_closes_stalled_connection(sink, audit, audit_stream) -> None:
    receiver = await make_receiver(sink, audit, partial_line_timeout=0.2)
    try:
        reader, writer = await open_connection(receiver)
        await send(writer, b'{"node_id": "canary-1"')
        remaining = await wait_for_eof(reader)
        writer.close()
    finally:
        await receiver.stop()

    assert remaining == b""
    assert ("connection_closed", "partial_line_timeout") in audit_actions(audit_stream)


async def test_silent_keepalive_connection_survives_timeout(sink, audit, event_factory) -> None:
    receiver = await make_receiver(sink, audit, partial_line_timeout=0.2)
    try:
        _reader, writer = await open_connection(receiver)
        await asyncio.sleep(0.6)
        await send(writer, (json.dumps(event_factory(), sort_keys=True) + "\n").encode())
        await sink.wait_for(1)
        writer.close()
        await writer.wait_closed()
    finally:
        await receiver.stop()

    assert len(sink.events) == 1


async def test_connection_limit_is_enforced(sink, audit, audit_stream) -> None:
    receiver = await make_receiver(sink, audit, max_connections=1)
    try:
        first_reader, first_writer = await open_connection(receiver)
        await asyncio.sleep(0.05)
        second_reader, second_writer = await open_connection(receiver)
        assert await wait_for_eof(second_reader) == b""
        second_writer.close()
        assert receiver.is_running
        assert first_reader.at_eof() is False
        first_writer.close()
        await first_writer.wait_closed()
    finally:
        await receiver.stop()

    assert ("connection_rejected", "connection_limit") in audit_actions(audit_stream)


async def test_rate_limited_events_are_not_delivered(sink, audit, audit_stream) -> None:
    class DenyEvents:
        async def allow_connection(self, source_ip: str) -> bool:
            return True

        async def allow_event(self, node_id: str) -> bool:
            return False

    receiver = await make_receiver(sink, audit, rate_limiter=DenyEvents())
    try:
        _reader, writer = await open_connection(receiver)
        await send(writer, b'{"node_id": "canary-1", "logtype": 2000}\n')
        await asyncio.sleep(0.2)
        writer.close()
        await writer.wait_closed()
    finally:
        await receiver.stop()

    assert sink.events == []
    assert receiver.stats.rate_limited == 1
    assert ("event_rate_limited", "") in audit_actions(audit_stream)


async def test_queue_overflow_drops_events_instead_of_growing(sink, audit) -> None:
    class BlockingSink(CollectingSink):
        def __init__(self) -> None:
            super().__init__()
            self.release = asyncio.Event()

        async def handle_event(self, event) -> None:
            await self.release.wait()
            await super().handle_event(event)

    blocking = BlockingSink()
    receiver = await make_receiver(blocking, audit, queue_size=1)
    try:
        _reader, writer = await open_connection(receiver)
        for index in range(6):
            await send(writer, f'{{"node_id": "canary-{index}"}}\n'.encode())
        await asyncio.sleep(0.2)
        assert receiver.stats.dropped >= 3
        blocking.release.set()
        await asyncio.sleep(0.2)
        writer.close()
        await writer.wait_closed()
    finally:
        await receiver.stop()


async def test_stats_track_accepted_and_connections(sink, audit, event_factory) -> None:
    receiver = await make_receiver(sink, audit)
    try:
        _reader, writer = await open_connection(receiver)
        await send(writer, (json.dumps(event_factory(), sort_keys=True) + "\n").encode())
        await sink.wait_for(1)
        writer.close()
        await writer.wait_closed()
    finally:
        await receiver.stop()

    assert receiver.stats.accepted == 1
    assert receiver.stats.connections == 1
    assert receiver.stats.rejected == 0


async def test_stop_is_idempotent(sink, audit) -> None:
    receiver = await make_receiver(sink, audit)
    await receiver.stop()
    await receiver.stop()

    assert receiver.is_running is False
