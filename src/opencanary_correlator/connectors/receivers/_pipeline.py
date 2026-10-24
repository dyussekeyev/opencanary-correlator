"""Bounded event pipeline shared by every receiver.

Receivers parse payloads synchronously inside protocol callbacks and hand the
resulting events to this pipeline. A single consumer task applies rate limits
and forwards events to the sink, so a slow sink never blocks the event loop and
memory stays bounded by ``queue_size``.
"""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass

from opencanary_correlator.audit import AuditLogger
from opencanary_correlator.connectors.base import EventSink, RateLimiter
from opencanary_correlator.schemas import CanaryEvent

DEFAULT_DRAIN_TIMEOUT: float = 5.0


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
    ) -> None:
        self.stats = ReceiverStats()
        self._sink = sink
        self._audit = audit
        self._rate_limiter = rate_limiter
        self._queue: asyncio.Queue[CanaryEvent] = asyncio.Queue(maxsize=queue_size)
        self._task: asyncio.Task[None] | None = None

    @property
    def pending(self) -> int:
        """Events waiting for the consumer."""
        return self._queue.qsize()

    async def start(self) -> None:
        """Start the consumer task."""
        if self._task is not None:
            return
        self._task = asyncio.create_task(self._consume(), name="event-pipeline")

    async def stop(self, *, drain_timeout: float = DEFAULT_DRAIN_TIMEOUT) -> None:
        """Drain what fits in `drain_timeout`, then stop the consumer."""
        if self._task is None:
            return
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(self._queue.join(), timeout=drain_timeout)
        self._task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self._task
        self._task = None

    def submit(self, event: CanaryEvent) -> bool:
        """Queue an event, dropping it (and auditing) when the queue is full."""
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            self.stats.dropped += 1
            self._audit.emit(
                "event_dropped",
                "error",
                {"reason": "queue_full", "node_id": event.node_id, "logtype": int(event.logtype)},
            )
            return False
        return True

    async def _consume(self) -> None:
        while True:
            event = await self._queue.get()
            try:
                if self._rate_limiter is not None and not await self._rate_limiter.allow_event(
                    event.node_id
                ):
                    self.stats.rate_limited += 1
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
                self._audit.emit(
                    "event_dispatch_failed",
                    "error",
                    {"node_id": event.node_id, "error_type": type(exc).__name__},
                )
            else:
                self.stats.accepted += 1
            finally:
                self._queue.task_done()


__all__ = ["DEFAULT_DRAIN_TIMEOUT", "EventPipeline", "ReceiverStats"]
