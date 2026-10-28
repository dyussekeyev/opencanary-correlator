"""Event deduplication: one fingerprint, one window."""

from __future__ import annotations

from opencanary_correlator.storage._base import _StoreBase
from opencanary_correlator.storage.keys import dedup_key


class _DedupMixin(_StoreBase):
    """First writer wins, until the fingerprint expires."""

    async def acquire_dedup(self, fingerprint: str, *, ttl: float) -> bool:
        """Return True the first time `fingerprint` is seen within `ttl`."""
        return bool(
            await self._client.set(
                dedup_key(fingerprint),
                "1",
                nx=True,
                px=max(1, int(ttl * 1000)),
            )
        )


__all__ = ["_DedupMixin"]
