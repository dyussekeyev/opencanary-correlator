"""Bounded event pipeline shared by every receiver.

Receivers parse payloads synchronously inside protocol callbacks and hand the
resulting events to this pipeline. Consumer lanes apply rate limits and forward
events to the sink, so a slow sink never blocks the event loop and memory stays
bounded by ``queue_size``.

Every event costs several Redis round trips (deduplication, the per-host lock,
the incident read and the incident write). One consumer would therefore cap
throughput at ``1 / round_trip_latency`` events per second no matter how fast
the server is. The pipeline runs ``concurrency`` lanes instead and shards events
by ``src_host``: different hosts progress in parallel, while every event from
one host keeps its arrival order, so incident merging stays deterministic and
replicas do not fight over the same lock.
"""

from __future__ import annotations

import asyncio
import zlib
from dataclasses import dataclass

from pydantic import ValidationError

from opencanary_correlator import metrics
from opencanary_correlator.audit import AuditLogger
from opencanary_correlator.connectors.base import EventSink, RateLimiter
from opencanary_correlator.schemas import CanaryEvent

DEFAULT_DRAIN_TIMEOUT: float = 5.0
DEFAULT_CONCURRENCY: int = 8


def schema_error_details(exc: ValidationError) -> dict[str, object]:
    """Describe the first schema error for a `schema_validation` audit record."""
    first = exc.errors()[0]
    return {
        "error_count": exc.error_count(),
        "first_error": ".".join(str(part) for part in first["loc"]) or "payload",
        "error_type": str(first["type"]),
    }


@dataclass(slots=True)
class ReceiverStats:
    """Counters exposed for health reporting and tests."""

    accepted: int = 0
    rejected: int = 0
    dropped: int = 0
    rate_limited: int = 0
    connections: int = 0


class EventPipeline:
    """Queue validated events and feed them to the sink under rate limits."""

    def __init__(
        self,
        *,
        sink: EventSink,
        audit: AuditLogger,
        queue_size: int,
        rate_limiter: RateLimiter | None = None,
        concurrency: int = DEFAULT_CONCURRENCY,
    ) -> None:
        self.stats = ReceiverStats()
        self._sink = sink
        self._audit = audit
        self._rate_limiter = rate_limiter
        self._concurrency = max(1, concurrency)
        # Share the configured budget between the lanes instead of multiplying
        # it, so total buffering still honours `queue_size`.
        per_lane = max(1, -(-queue_size // self._concurrency))
        self._queues: tuple[asyncio.Queue[CanaryEvent], ...] = tuple(
            asyncio.Queue(maxsize=per_lane) for _ in range(self._concurrency)
        )
        self._tasks: list[asyncio.Task[None]] = []

    @property
    def concurrency(self) -> int:
        """Number of consumer lanes."""
        return self._concurrency

    @property
    def pending(self) -> int:
        """Events waiting for the consumers."""
        return sum(queue.qsize() for queue in self._queues)

    async def start(self) -> None:
        """Start one consumer task per lane."""
        if self._tasks:
            return
        self._tasks = [
            asyncio.create_task(self._consume(queue), name=f"event-pipeline-{index}")
            for index, queue in enumerate(self._queues)
        ]

    async def stop(self, *, drain_timeout: float = DEFAULT_DRAIN_TIMEOUT) -> None:
        """Drain what fits in `drain_timeout`, then stop every consumer.

        A backlog that does not fit is cancelled with the consumers, so it is
        counted and audited first: an event dropped at shutdown leaves no other
        trace, and a restart's backlog used to disappear without a record.
        """
        if not self._tasks:
            return
        try:
            await asyncio.wait_for(
                asyncio.gather(*(queue.join() for queue in self._queues)),
                timeout=drain_timeout,
            )
        except TimeoutError:
            lost = self.pending
            if lost:
                self.stats.dropped += lost
                metrics.EVENTS_TOTAL.labels(result="dropped").inc(lost)
                metrics.EVENTS_DROPPED.labels(reason="shutdown").inc(lost)
                self._audit.emit(
                    "event_dropped",
                    "warning",
                    {"reason": "shutdown", "count": lost},
                )
            for queue in self._queues:
                while not queue.empty():
                    queue.get_nowait()
            metrics.EVENT_QUEUE_DEPTH.set(self.pending)
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks = []

    def record_rejection(self) -> None:
        """Count a payload that failed validation before it reached the queue."""
        self.stats.rejected += 1
        metrics.EVENTS_TOTAL.labels(result="rejected").inc()

    def record_ignored(self, reason: str) -> None:
        """Count a payload that was read but carried nothing to correlate.

        A frame of framing alone (a keep-alive newline, or `SysLogHandler`'s NUL)
        is not a rejection: counting it as one hides a genuine rejection in a
        metric an operator reads to spot a canary that stopped being understood.
        """
        metrics.EVENTS_TOTAL.labels(result="ignored").inc()
        self._audit.emit("event_ignored", "info", {"reason": reason})

    def submit(self, event: CanaryEvent) -> bool:
        """Queue an event, dropping it (and auditing) when its lane is full."""
        queue = self._queue_for(event)
        try:
            queue.put_nowait(event)
        except asyncio.QueueFull:
            self.stats.dropped += 1
            metrics.EVENTS_TOTAL.labels(result="dropped").inc()
            metrics.EVENTS_DROPPED.labels(reason="queue_full").inc()
            metrics.EVENT_QUEUE_DEPTH.set(self.pending)
            self._audit.emit(
                "event_dropped",
                "error",
                {"reason": "queue_full", "node_id": event.node_id, "logtype": int(event.logtype)},
            )
            return False
        metrics.EVENT_QUEUE_DEPTH.set(self.pending)
        return True

    def _queue_for(self, event: CanaryEvent) -> asyncio.Queue[CanaryEvent]:
        """Pick the lane that owns this event's source host.

        ``crc32`` keeps the mapping stable across processes, which makes the
        lane a host is handled by predictable when reading logs. With a single
        lane there is nothing to shard.
        """
        if self._concurrency == 1:
            return self._queues[0]
        lane = zlib.crc32(event.src_host.encode("utf-8", "surrogatepass")) % self._concurrency
        return self._queues[lane]

    async def _consume(self, queue: asyncio.Queue[CanaryEvent]) -> None:
        while True:
            event = await queue.get()
            metrics.EVENT_QUEUE_DEPTH.set(self.pending)
            try:
                if self._rate_limiter is not None and not await self._rate_limiter.allow_event(
                    event.node_id
                ):
                    self.stats.rate_limited += 1
                    metrics.EVENTS_TOTAL.labels(result="rate_limited").inc()
                    self._audit.emit(
                        "event_rate_limited",
                        "warning",
                        {"node_id": event.node_id, "logtype": int(event.logtype)},
                    )
                    continue
                await self._sink.handle_event(event)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.stats.dropped += 1
                metrics.EVENTS_TOTAL.labels(result="dropped").inc()
                metrics.EVENTS_DROPPED.labels(reason="dispatch_failed").inc()
                self._audit.emit(
                    "event_dispatch_failed",
                    "error",
                    {"node_id": event.node_id, "error_type": type(exc).__name__},
                )
            else:
                self.stats.accepted += 1
                metrics.EVENTS_TOTAL.labels(result="accepted").inc()
            finally:
                queue.task_done()
                metrics.EVENT_QUEUE_DEPTH.set(self.pending)


__all__ = [
    "DEFAULT_CONCURRENCY",
    "DEFAULT_DRAIN_TIMEOUT",
    "EventPipeline",
    "ReceiverStats",
    "schema_error_details",
]
