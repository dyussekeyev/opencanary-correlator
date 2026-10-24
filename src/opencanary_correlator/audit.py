"""JSON audit trail for the correlator.

Every record is one JSON object per line with the fields required by
``docs/EXECPLAN-refactor.md``: ``timestamp``, ``component``, ``action``,
``status`` and ``details``. Details pass through secret redaction and
log-injection sanitisation, so attacker-controlled honeypot data can never
forge a line or leak a captured password.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import sys
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, Final, Literal, Protocol, TextIO

from pydantic import BaseModel, ConfigDict, Field

from opencanary_correlator.redaction import redact_mapping

AuditStatus = Literal["success", "error", "info", "warning"]

_NAME_PATTERN: Final[str] = r"^[a-z0-9][a-z0-9_.-]*$"
_DEFAULT_SHUTDOWN_TIMEOUT: Final[float] = 5.0


class AuditEvent(BaseModel):
    """One line of the audit trail."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    component: str = Field(min_length=1, max_length=64, pattern=_NAME_PATTERN)
    action: str = Field(min_length=1, max_length=64, pattern=_NAME_PATTERN)
    status: AuditStatus
    details: dict[str, Any] = Field(default_factory=dict)

    def to_json_line(self) -> str:
        """Serialise to a single JSON line without embedded newlines."""
        return self.model_dump_json()


class AuditLogger:
    """Write :class:`AuditEvent` records to a stream, one JSON object per line."""

    def __init__(self, component: str, stream: TextIO | None = None) -> None:
        self._component = component
        self._stream: TextIO = stream if stream is not None else sys.stdout

    @property
    def component(self) -> str:
        """Component name attached to every record from this logger."""
        return self._component

    def emit(
        self,
        action: str,
        status: AuditStatus,
        details: Mapping[str, Any] | None = None,
    ) -> AuditEvent:
        """Write one audit record and return it.

        Failures to write are reported on stderr instead of propagating: an
        audit sink going away must not take the correlator down.
        """
        record = AuditEvent(
            component=self._component,
            action=action,
            status=status,
            details=redact_mapping(details or {}),
        )
        line = record.to_json_line()
        try:
            self._stream.write(f"{line}\n")
            self._stream.flush()
        except (OSError, ValueError):
            print(line, file=sys.stderr, flush=True)
        return record


class LogSink(Protocol):
    """Async sink for the bounded log list shared with the legacy console."""

    async def push_log(self, line: str, *, max_entries: int) -> None:
        """Append `line`, trimming the list to `max_entries` entries."""
        ...


class RedisLogHandler(logging.Handler):
    """Bridge stdlib logging to an async bounded log sink.

    Records are buffered in a bounded queue so a slow or unavailable Redis can
    never block a receiver. Overflow is counted in :attr:`dropped` and reported
    by the caller instead of silently growing memory.
    """

    def __init__(
        self,
        sink: LogSink,
        *,
        queue_size: int = 1000,
        max_entries: int = 1000,
        shutdown_timeout: float = _DEFAULT_SHUTDOWN_TIMEOUT,
        level: int = logging.NOTSET,
    ) -> None:
        super().__init__(level=level)
        self._sink = sink
        self._max_entries = max_entries
        self._shutdown_timeout = shutdown_timeout
        self._queue: asyncio.Queue[str] = asyncio.Queue(maxsize=queue_size)
        self._task: asyncio.Task[None] | None = None
        self._dropped = 0

    @property
    def dropped(self) -> int:
        """Number of records dropped because the queue or sink failed."""
        return self._dropped

    @property
    def pending(self) -> int:
        """Number of records waiting to reach the sink."""
        return self._queue.qsize()

    def emit(self, record: logging.LogRecord) -> None:
        """Queue a formatted record without ever raising."""
        try:
            self._queue.put_nowait(self.format(record))
        except asyncio.QueueFull:
            self._dropped += 1
        except Exception:
            self.handleError(record)

    async def start(self) -> None:
        """Start the background drain task."""
        if self._task is not None:
            return
        self._task = asyncio.create_task(self._drain(), name="redis-log-handler")

    async def stop(self) -> None:
        """Flush what fits in the timeout, then cancel the drain task."""
        if self._task is None:
            return
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(self._queue.join(), timeout=self._shutdown_timeout)
        self._task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self._task
        self._task = None

    async def _drain(self) -> None:
        while True:
            line = await self._queue.get()
            try:
                await self._sink.push_log(line, max_entries=self._max_entries)
            except Exception:
                self._dropped += 1
            finally:
                self._queue.task_done()


__all__ = [
    "AuditEvent",
    "AuditLogger",
    "AuditStatus",
    "LogSink",
    "RedisLogHandler",
]
