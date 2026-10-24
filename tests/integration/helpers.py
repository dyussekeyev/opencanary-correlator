"""Helpers shared by the socket-level receiver tests."""

from __future__ import annotations

import asyncio
import io
import json
from typing import Any

from opencanary_correlator.schemas import CanaryEvent


class CollectingSink:
    """Event sink that records everything and can be awaited."""

    def __init__(self) -> None:
        self.events: list[CanaryEvent] = []
        self._changed = asyncio.Event()

    async def handle_event(self, event: CanaryEvent) -> None:
        self.events.append(event)
        self._changed.set()

    async def wait_for(self, count: int = 1, timeout: float = 3.0) -> list[CanaryEvent]:
        """Wait until `count` events arrived, then return them."""

        async def _wait() -> None:
            while len(self.events) < count:
                self._changed.clear()
                await self._changed.wait()

        await asyncio.wait_for(_wait(), timeout=timeout)
        return self.events


def audit_records(stream: io.StringIO) -> list[dict[str, Any]]:
    """Parse the JSON-lines audit stream."""
    return [json.loads(line) for line in stream.getvalue().splitlines() if line.strip()]


def audit_actions(stream: io.StringIO) -> list[tuple[str, str]]:
    """Return `(action, reason)` pairs from the audit stream."""
    return [
        (record["action"], str(record["details"].get("reason", "")))
        for record in audit_records(stream)
    ]


async def wait_for_eof(reader: asyncio.StreamReader, timeout: float = 3.0) -> bytes:
    """Read until the peer closes, returning whatever bytes were received."""
    return await asyncio.wait_for(reader.read(), timeout=timeout)
