"""Consumer lanes: per-host ordering, cross-host parallelism and backpressure."""

from __future__ import annotations

import asyncio
import json
from collections import defaultdict
from types import SimpleNamespace
from typing import Any

from opencanary_correlator import metrics
from opencanary_correlator.connectors.receivers._pipeline import EventPipeline
from opencanary_correlator.connectors.receivers.tcp_json import TCPJSONReceiver
from opencanary_correlator.schemas import CanaryEvent


def drops(reason: str) -> float:
    """Current value of a drop counter; the registry is process-global."""
    return metrics.EVENTS_DROPPED.labels(reason=reason)._value.get()


class RecordingSink:
    """Sink that records delivery order per source host."""

    def __init__(self, *, delay: float = 0.0) -> None:
        self.orders: dict[str, list[int]] = defaultdict(list)
        self.active = 0
        self.max_active = 0
        self._delay = delay

    async def handle_event(self, event: CanaryEvent) -> None:
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        try:
            if self._delay:
                await asyncio.sleep(self._delay)
            self.orders[event.src_host].append(event.src_port)
        finally:
            self.active -= 1


def make_event(src_host: str, src_port: int) -> CanaryEvent:
    """Build a minimal event whose payload order is visible in `src_port`."""
    return CanaryEvent.model_validate(
        {
            "src_host": src_host,
            "src_port": src_port,
            "node_id": "canary-1",
            "logtype": 2000,
        }
    )


async def test_single_lane_delivers_everything_in_order(audit: Any) -> None:
    sink = RecordingSink()
    pipeline = EventPipeline(sink=sink, audit=audit, queue_size=100, concurrency=1)
    await pipeline.start()
    try:
        for port in range(50):
            assert pipeline.submit(make_event("10.0.0.5", port))
        await asyncio.wait_for(pipeline._queues[0].join(), timeout=5)
    finally:
        await pipeline.stop()

    assert pipeline.concurrency == 1
    assert sink.orders["10.0.0.5"] == list(range(50))
    assert pipeline.stats.accepted == 50


async def test_per_host_order_is_preserved_across_lanes(audit: Any) -> None:
    sink = RecordingSink(delay=0.001)
    pipeline = EventPipeline(sink=sink, audit=audit, queue_size=1000, concurrency=8)
    await pipeline.start()
    try:
        for port in range(200):
            assert pipeline.submit(make_event(f"10.0.1.{port % 10}", port))
        await asyncio.wait_for(
            asyncio.gather(*(queue.join() for queue in pipeline._queues)), timeout=10
        )
    finally:
        await pipeline.stop()

    for host, ports in sink.orders.items():
        assert ports == sorted(ports), host
    assert sum(len(ports) for ports in sink.orders.values()) == 200


async def test_lanes_overlap_slow_hosts(audit: Any) -> None:
    """A slow dispatch for one host must not serialise the other hosts."""
    sink = RecordingSink(delay=0.01)
    pipeline = EventPipeline(sink=sink, audit=audit, queue_size=100, concurrency=4)
    await pipeline.start()
    try:
        for index in range(4):
            assert pipeline.submit(make_event(f"10.0.2.{index}", index))
        await asyncio.wait_for(
            asyncio.gather(*(queue.join() for queue in pipeline._queues)), timeout=5
        )
    finally:
        await pipeline.stop()

    assert sink.max_active > 1


async def test_a_full_lane_drops_and_audits(audit: Any, audit_stream: Any) -> None:
    sink = RecordingSink()
    pipeline = EventPipeline(sink=sink, audit=audit, queue_size=1, concurrency=1)
    before = drops("queue_full")
    await pipeline.start()
    try:
        assert pipeline.submit(make_event("10.0.0.5", 1))
        # The consumer may already have taken the first event, so fill until a
        # drop happens instead of assuming the queue is still occupied.
        dropped = False
        for port in range(2, 200):
            if not pipeline.submit(make_event("10.0.0.5", port)):
                dropped = True
                break
        assert dropped
    finally:
        await pipeline.stop()

    assert pipeline.stats.dropped >= 1
    assert "event_dropped" in audit_stream.getvalue()
    # The reason has to be visible in a scrape, not only in the audit line.
    assert drops("queue_full") > before


async def test_a_backlog_cancelled_at_shutdown_is_counted_and_audited(
    audit: Any, audit_stream: Any
) -> None:
    """A restart must not swallow queued events without a record.

    `stop()` cancels the consumer tasks when the drain budget runs out, and every
    event still in a queue dies with them. That was the one drop path with no
    audit record and no counter, so a busy restart looked like events that were
    never sent.
    """
    sink = RecordingSink(delay=0.5)
    pipeline = EventPipeline(sink=sink, audit=audit, queue_size=50, concurrency=1)
    before = drops("shutdown")
    await pipeline.start()
    for port in range(5):
        assert pipeline.submit(make_event("10.0.0.5", port))

    await pipeline.stop(drain_timeout=0.01)

    records = [
        json.loads(line) for line in audit_stream.getvalue().splitlines() if "event_dropped" in line
    ]
    assert len(records) == 1
    assert records[0]["details"]["reason"] == "shutdown"
    assert records[0]["details"]["count"] >= 1
    assert pipeline.stats.dropped == records[0]["details"]["count"]
    assert drops("shutdown") - before == records[0]["details"]["count"]
    assert pipeline.pending == 0


async def test_a_blank_frame_is_ignored_instead_of_rejected(audit: Any, audit_stream: Any) -> None:
    """Framing-only payloads must not inflate the rejection counter.

    `SocketJSONHandler` and `SysLogHandler` leave stray newlines and NULs, and a
    rejection counter that counts them cannot answer "did the canary send
    something we failed to parse?".
    """
    receiver = TCPJSONReceiver(sink=RecordingSink(), audit=audit)
    protocol = SimpleNamespace(peer_ip="10.0.0.9")

    receiver.payload_received(protocol, b"\n")
    receiver.payload_received(protocol, b"  \r\n")

    assert receiver.stats.rejected == 0
    assert receiver.pending == 0
    assert audit_stream.getvalue().count("empty_payload") == 2


async def test_queue_budget_is_shared_between_lanes(audit: Any) -> None:
    pipeline = EventPipeline(sink=RecordingSink(), audit=audit, queue_size=100, concurrency=8)

    total = sum(queue.maxsize for queue in pipeline._queues)

    assert pipeline.concurrency == 8
    # Per-lane sizes are rounded up, so the total never exceeds the budget by
    # more than one event per lane.
    assert 100 <= total < 100 + pipeline.concurrency


async def test_stop_cancels_idle_lanes(audit: Any) -> None:
    pipeline = EventPipeline(sink=RecordingSink(), audit=audit, queue_size=10, concurrency=4)
    await pipeline.start()
    tasks: list[Any] = list(pipeline._tasks)

    await pipeline.stop()

    assert all(task.done() for task in tasks)
    assert pipeline._tasks == []


class NodeLimiter:
    """Limiter with a budget per node, shared by every lane."""

    def __init__(self, *, budget: int) -> None:
        self.budget = budget
        self.seen: list[str] = []

    async def allow_connection(self, source_ip: str) -> bool:  # pragma: no cover - unused
        return True

    async def allow_event(self, node_id: str) -> bool:
        self.seen.append(node_id)
        return len(self.seen) <= self.budget


async def test_an_event_over_the_node_budget_is_never_delivered(
    audit: Any, audit_stream: Any
) -> None:
    """The per-node budget must apply inside the lane, not only in the limiter.

    A limiter that is consulted and then ignored would let a chatty canary flood
    correlation while every unit test of the limiter stayed green.
    """
    sink = RecordingSink()
    pipeline = EventPipeline(
        sink=sink,
        audit=audit,
        queue_size=100,
        concurrency=1,
        rate_limiter=NodeLimiter(budget=2),
    )
    await pipeline.start()
    try:
        for port in range(5):
            pipeline.submit(make_event("10.0.0.5", port))
        await asyncio.wait_for(pipeline._queues[0].join(), timeout=5)
    finally:
        await pipeline.stop()

    assert sink.orders["10.0.0.5"] == [0, 1]
    assert pipeline.stats.accepted == 2
    assert pipeline.stats.rate_limited == 3
    assert audit_stream.getvalue().count("event_rate_limited") == 3


class FailingSink:
    """Sink that refuses the first event only."""

    def __init__(self) -> None:
        self.delivered: list[int] = []

    async def handle_event(self, event: CanaryEvent) -> None:
        if event.src_port == 0:
            raise RuntimeError("engine exploded")
        self.delivered.append(event.src_port)


async def test_a_sink_error_does_not_kill_the_lane(audit: Any, audit_stream: Any) -> None:
    """One failing event must cost that event, not every later one.

    If the exception escaped `_consume`, the lane would die silently and every
    later event from those hosts would be queued and never processed.
    """
    sink = FailingSink()
    pipeline = EventPipeline(sink=sink, audit=audit, queue_size=100, concurrency=1)
    await pipeline.start()
    try:
        pipeline.submit(make_event("10.0.0.5", 0))
        pipeline.submit(make_event("10.0.0.5", 1))
        await asyncio.wait_for(pipeline._queues[0].join(), timeout=5)
    finally:
        await pipeline.stop()

    assert sink.delivered == [1]
    assert pipeline.stats.dropped == 1
    assert pipeline.stats.accepted == 1
    failure = [
        line for line in audit_stream.getvalue().splitlines() if "event_dispatch_failed" in line
    ]
    assert len(failure) == 1
    assert "RuntimeError" in failure[0]
