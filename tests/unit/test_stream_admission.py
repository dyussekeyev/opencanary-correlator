"""Admission before the first payload is parsed.

A `SocketJSONHandler` writes its first event immediately after connecting, while
the per-peer budget is answered asynchronously. Parsing that event before the
answer is what let an over-quota peer still deliver one event per connection, and
what made a limiter outage invisible in the pipeline until the audit record
landed. The protocol therefore holds the bytes - a single frame's worth - and the
receiver releases them when the budget says yes (or when it cannot be read).
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from opencanary_correlator.connectors.receivers._stream import (
    CLOSE_REASON_LINE_TOO_LARGE,
    CLOSE_REASON_RATE_LIMITED,
)
from opencanary_correlator.connectors.receivers._tcp import StreamProtocol
from opencanary_correlator.connectors.receivers.tcp_json import TCPJSONProtocol, TCPJSONReceiver


class GatedLimiter:
    """A budget whose answer the test releases by hand."""

    def __init__(self, *, allow: bool = True) -> None:
        self.gate = asyncio.Event()
        self.allow = allow
        self.calls: list[str] = []

    async def allow_connection(self, source_ip: str) -> bool:
        self.calls.append(source_ip)
        await self.gate.wait()
        return self.allow

    async def allow_event(self, node_id: str) -> bool:  # pragma: no cover - unused here
        return True


class RecordingSink:
    """Sink that is never reached: the pipeline is inspected before it runs."""

    def __init__(self) -> None:
        self.events: list[Any] = []

    async def handle_event(self, event: Any) -> None:
        self.events.append(event)


class FakeTransport:
    """What the protocol asks a transport, and nothing else."""

    def __init__(self) -> None:
        self.closed = False

    def get_extra_info(self, name: str) -> Any:
        if name == "peername":
            return ("10.0.0.9", 5555)
        return None

    def close(self) -> None:
        self.closed = True


def make_receiver(audit: Any, limiter: Any) -> TCPJSONReceiver:
    return TCPJSONReceiver(
        host="127.0.0.1",
        port=0,
        sink=RecordingSink(),
        audit=audit,
        rate_limiter=limiter,
        max_line_bytes=1024,
    )


def connect(receiver: TCPJSONReceiver) -> tuple[StreamProtocol, FakeTransport]:
    protocol = TCPJSONProtocol(receiver)
    transport = FakeTransport()
    protocol.connection_made(transport)
    return protocol, transport


async def settle(receiver: TCPJSONReceiver) -> None:
    """Wait for the admission task the receiver scheduled."""
    await asyncio.gather(*receiver._admission_tasks)


def audit_records(audit_stream: Any) -> list[dict[str, Any]]:
    return [json.loads(line) for line in audit_stream.getvalue().splitlines() if line.strip()]


async def test_a_payload_waits_for_the_budget_before_it_is_parsed(
    audit: Any, event_line: Any
) -> None:
    limiter = GatedLimiter()
    receiver = make_receiver(audit, limiter)
    protocol, _transport = connect(receiver)

    protocol.data_received(event_line())

    # The line is held, not parsed: nothing reached the event pipeline yet.
    assert receiver.pending == 0

    limiter.gate.set()
    await settle(receiver)

    assert receiver.pending == 1


async def test_a_refused_connection_never_parses_its_payload(
    audit: Any, audit_stream: Any, event_line: Any
) -> None:
    """`SocketJSONHandler` writes first; the budget still has the last word."""
    limiter = GatedLimiter(allow=False)
    receiver = make_receiver(audit, limiter)
    protocol, transport = connect(receiver)

    protocol.data_received(event_line())
    limiter.gate.set()
    await settle(receiver)

    assert receiver.pending == 0
    assert transport.closed is True
    rejected = [
        record
        for record in audit_records(audit_stream)
        if record["action"] == "connection_rejected"
    ]
    assert rejected[0]["details"]["reason"] == CLOSE_REASON_RATE_LIMITED
    # Nothing was parsed, so nothing was rejected either: the payload never
    # existed as far as the pipeline is concerned.
    assert not [r for r in audit_records(audit_stream) if r["action"] == "event_rejected"]


async def test_a_payload_written_then_closed_is_not_lost(audit: Any, event_line: Any) -> None:
    """`SocketJSONHandler` sends one event per connection and closes at once.

    The budget is a Redis round trip, so the peer's FIN routinely arrives first.
    The bytes were received while the socket was open and must still be
    correlated; the CI compose smoke test failed exactly here when the payload
    was held and then thrown away with the closed transport.
    """
    limiter = GatedLimiter()
    receiver = make_receiver(audit, limiter)
    protocol, _transport = connect(receiver)

    protocol.data_received(event_line())
    protocol.connection_lost(None)
    limiter.gate.set()
    await settle(receiver)

    assert receiver.pending == 1


async def test_a_frame_split_across_the_decision_is_still_joined(
    audit: Any, event_line: Any
) -> None:
    """The byte buffer survives the wait, so framing is intact either side of it."""
    limiter = GatedLimiter()
    receiver = make_receiver(audit, limiter)
    protocol, _transport = connect(receiver)
    line = event_line()

    protocol.data_received(line[:10])
    limiter.gate.set()
    await settle(receiver)
    protocol.data_received(line[10:])

    assert receiver.pending == 1


async def test_an_oversized_line_is_refused_while_the_decision_is_pending(
    audit: Any, audit_stream: Any
) -> None:
    """A pending connection must not buffer more than one frame."""
    limiter = GatedLimiter()
    receiver = make_receiver(audit, limiter)
    protocol, transport = connect(receiver)

    protocol.data_received(b"x" * (receiver.max_line_bytes + 1))

    assert transport.closed is True
    closed = [r for r in audit_records(audit_stream) if r["action"] == "connection_closed"]
    assert closed[0]["details"]["reason"] == CLOSE_REASON_LINE_TOO_LARGE

    # The answer arrives afterwards; a closed connection must not resurrect it.
    limiter.gate.set()
    await settle(receiver)
    assert receiver.pending == 0


async def test_without_a_limiter_a_payload_is_processed_immediately(
    audit: Any, event_line: Any
) -> None:
    """The default deployment keeps the synchronous path it always had."""
    receiver = make_receiver(audit, None)
    protocol, _transport = connect(receiver)

    protocol.data_received(event_line())

    assert receiver.pending == 1
    assert receiver._admission_tasks == set()
