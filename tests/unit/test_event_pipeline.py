"""Consumer lanes: per-host ordering, cross-host parallelism and backpressure."""

from __future__ import annotations

import asyncio
from collections import defaultdict
from typing import Any

from opencanary_correlator.connectors.receivers._pipeline import EventPipeline
from opencanary_correlator.schemas import CanaryEvent


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


async def test_single_lane_delivers_everything_in_order(audit) -> None:
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


async def test_per_host_order_is_preserved_across_lanes(audit) -> None:
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


async def test_lanes_overlap_slow_hosts(audit) -> None:
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


async def test_a_full_lane_drops_and_audits(audit, audit_stream) -> None:
    sink = RecordingSink()
    pipeline = EventPipeline(sink=sink, audit=audit, queue_size=1, concurrency=1)
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


async def test_queue_budget_is_shared_between_lanes(audit) -> None:
    pipeline = EventPipeline(sink=RecordingSink(), audit=audit, queue_size=100, concurrency=8)

    total = sum(queue.maxsize for queue in pipeline._queues)

    assert pipeline.concurrency == 8
    # Per-lane sizes are rounded up, so the total never exceeds the budget by
    # more than one event per lane.
    assert 100 <= total < 100 + pipeline.concurrency


async def test_stop_cancels_idle_lanes(audit) -> None:
    pipeline = EventPipeline(sink=RecordingSink(), audit=audit, queue_size=10, concurrency=4)
    await pipeline.start()
    tasks: list[Any] = list(pipeline._tasks)

    await pipeline.stop()

    assert all(task.done() for task in tasks)
    assert pipeline._tasks == []
