"""A short-lived distributed lock, released only by its owner."""

from __future__ import annotations

import asyncio
import contextlib
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from redis.exceptions import RedisError

from opencanary_correlator.storage._base import _StoreBase

DEFAULT_LOCK_TTL_MS: int = 5_000
DEFAULT_LOCK_WAIT_SECONDS: float = 5.0
LOCK_RETRY_INTERVAL_SECONDS: float = 0.01


class _LockMixin(_StoreBase):
    """Serialise incident creation across replicas."""

    @asynccontextmanager
    async def lock(
        self,
        key: str,
        *,
        ttl_ms: int = DEFAULT_LOCK_TTL_MS,
        wait_timeout: float = DEFAULT_LOCK_WAIT_SECONDS,
    ) -> AsyncIterator[bool]:
        """Acquire a best-effort distributed lock, yielding False on timeout."""
        token = uuid.uuid4().hex
        loop = asyncio.get_running_loop()
        deadline = loop.time() + wait_timeout
        acquired = False
        while True:
            acquired = bool(await self._client.set(key, token, nx=True, px=max(1, ttl_ms)))
            if acquired or loop.time() >= deadline:
                break
            await asyncio.sleep(LOCK_RETRY_INTERVAL_SECONDS)
        try:
            yield acquired
        finally:
            if acquired:
                with contextlib.suppress(RedisError):
                    await self._release_lock(key, token)

    async def _release_lock(self, key: str, token: str) -> bool:
        """Delete `key` only while it still holds `token`, atomically.

        A plain GET followed by DEL is racy: if the TTL expires between the two
        calls, another replica can acquire the lock and the first replica would
        delete the new owner's lock. The script compares and deletes in one
        atomic round trip.
        """
        released = await self._run_script(self._release_lock_script, [key], [token])
        return bool(released)


__all__ = [
    "DEFAULT_LOCK_TTL_MS",
    "DEFAULT_LOCK_WAIT_SECONDS",
    "LOCK_RETRY_INTERVAL_SECONDS",
    "_LockMixin",
]
