"""The legacy console journal: a bounded list of log lines."""

from __future__ import annotations

from collections.abc import Awaitable
from typing import Any, cast

from opencanary_correlator.constants import KEY_LOGS
from opencanary_correlator.storage._base import _StoreBase


class _ConsoleMixin(_StoreBase):
    """Append-only, bounded journal for operators migrating from 0.1."""

    async def lpush_trim(self, key: str, value: str, *, max_entries: int) -> None:
        """Push a log line and keep the list bounded."""
        async with self._client.pipeline(transaction=True) as pipe:
            pipe.lpush(key, value)
            pipe.ltrim(key, 0, max(0, max_entries - 1))
            await pipe.execute()

    async def push_log(self, line: str, *, max_entries: int) -> None:
        """Append a console log line to the bounded legacy `logs` list."""
        await self.lpush_trim(KEY_LOGS, line, max_entries=max_entries)

    async def lrange(self, key: str, start: int = 0, end: int = -1) -> list[str]:
        """Read a list range."""
        pending = cast(Awaitable[Any], self._client.lrange(key, start, end))
        values = await pending
        return [self._text(value) for value in values]


__all__ = ["_ConsoleMixin"]
