"""Connection admission: the distributed budget, and what a limiter failure does.

`_admit` runs as a task scheduled by `connection_made`, so nothing in the suite
ever awaited it: the connection budget existed, ran in production, and was never
exercised. The three outcomes have three very different failure modes, which is
why each has its own test:

* allowed - the socket must stay open;
* denied - the socket must be closed and the reason audited;
* limiter raising - the socket must **stay** open. A Redis outage must not lock
  every canary out of the correlator, and the error must be visible at ERROR.
"""

from __future__ import annotations

import asyncio
from typing import Any

from opencanary_correlator.connectors.receivers._tcp import (
    CLOSE_REASON_RATE_LIMITED,
    TCPStreamReceiver,
)
from opencanary_correlator.connectors.receivers.tcp_json import TCPJSONReceiver


class FakeLimiter:
    """Limiter whose verdict, or failure, the test decides."""

    def __init__(self, *, allow: bool = True, error: Exception | None = None) -> None:
        self.allow = allow
        self.error = error
        self.connection_calls: list[str] = []

    async def allow_connection(self, source_ip: str) -> bool:
        self.connection_calls.append(source_ip)
        if self.error is not None:
            raise self.error
        return self.allow

    async def allow_event(self, node_id: str) -> bool:  # pragma: no cover - not used here
        return True


class FakeProtocol:
    """What `_admit` needs from a connection, and a record of how it was closed."""

    def __init__(self, peer_ip: str = "10.0.0.5") -> None:
        self.peer_ip = peer_ip
        self.closed_with: list[str] = []
        self.admitted = False

    def close(self, reason: str) -> None:
        self.closed_with.append(reason)

    def admit(self) -> None:
        self.admitted = True


class RecordingSink:
    """Sink that accepts and forgets; the socket, not the engine, is under test."""

    async def handle_event(self, event: Any) -> None:  # pragma: no cover - not reached
        return None


def make_receiver(audit: Any, limiter: FakeLimiter | None) -> TCPStreamReceiver:
    """A receiver that is never started: admission does not need a listener."""
    return TCPJSONReceiver(
        host="127.0.0.1",
        port=0,
        sink=RecordingSink(),
        audit=audit,
        rate_limiter=limiter,
    )


def records(audit_stream: Any) -> list[dict[str, Any]]:
    import json

    return [json.loads(line) for line in audit_stream.getvalue().splitlines() if line.strip()]


async def test_a_denied_connection_is_closed_and_audited(audit: Any, audit_stream: Any) -> None:
    """A limiter saying no must close the socket, not quietly keep it."""
    limiter = FakeLimiter(allow=False)
    receiver = make_receiver(audit, limiter)
    protocol = FakeProtocol()

    receiver.connection_made(protocol)  # type: ignore[arg-type]
    await asyncio.gather(*receiver._admission_tasks)

    assert limiter.connection_calls == ["10.0.0.5"]
    assert protocol.closed_with == [CLOSE_REASON_RATE_LIMITED]
    assert protocol.admitted is False
    rejected = [r for r in records(audit_stream) if r["action"] == "connection_rejected"]
    assert len(rejected) == 1
    assert rejected[0]["details"]["reason"] == CLOSE_REASON_RATE_LIMITED
    assert rejected[0]["details"]["peer"] == "10.0.0.5"


async def test_an_allowed_connection_is_left_open(audit: Any, audit_stream: Any) -> None:
    limiter = FakeLimiter(allow=True)
    receiver = make_receiver(audit, limiter)
    protocol = FakeProtocol()

    receiver.connection_made(protocol)  # type: ignore[arg-type]
    await asyncio.gather(*receiver._admission_tasks)

    assert protocol.closed_with == []
    assert protocol.admitted is True
    assert not [r for r in records(audit_stream) if r["action"] == "connection_rejected"]


async def test_a_limiter_failure_is_audited_and_keeps_the_connection(
    audit: Any, audit_stream: Any
) -> None:
    """A Redis outage must not cost every canary its socket.

    Closing on error would turn a limiter incident into a correlator outage: the
    canary reconnects, fails again, and nothing is delivered. The connection stays
    open and the failure is audited at ERROR so the operator sees the real cause.
    """
    limiter = FakeLimiter(error=RuntimeError("redis down"))
    receiver = make_receiver(audit, limiter)
    protocol = FakeProtocol()

    receiver.connection_made(protocol)  # type: ignore[arg-type]
    await asyncio.gather(*receiver._admission_tasks)

    assert protocol.closed_with == []
    # Fail open includes the payloads that waited for the answer.
    assert protocol.admitted is True
    failures = [r for r in records(audit_stream) if r["action"] == "connection_limiter_error"]
    assert len(failures) == 1
    assert failures[0]["status"] == "error"
    assert failures[0]["details"]["error_type"] == "RuntimeError"


async def test_no_admission_task_is_scheduled_without_a_limiter(audit: Any) -> None:
    receiver = make_receiver(audit, None)
    protocol = FakeProtocol()

    receiver.connection_made(protocol)  # type: ignore[arg-type]

    assert receiver._admission_tasks == set()
    assert protocol.closed_with == []


class HangingLimiter:
    """Limiter whose connection check never answers, like a stalled Redis."""

    async def allow_connection(self, source_ip: str) -> bool:
        import asyncio

        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    async def allow_event(self, node_id: str) -> bool:  # pragma: no cover - unused
        return True


async def test_stop_closes_live_peers_and_cancels_pending_admission(audit: Any) -> None:
    """A shutdown must not leave a canary's socket half-open or a task pending."""
    receiver = make_receiver(audit, HangingLimiter())
    protocol = FakeProtocol()
    receiver.connection_made(protocol)  # type: ignore[arg-type]
    assert receiver._admission_tasks

    await receiver.stop()

    assert protocol.closed_with == ["shutdown"]
    assert receiver._admission_tasks == set()
