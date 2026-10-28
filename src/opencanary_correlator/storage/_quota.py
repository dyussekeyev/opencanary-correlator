"""Quota reservations for a rate-limited third party."""

from __future__ import annotations

from collections.abc import Sequence

from opencanary_correlator.storage._base import _StoreBase


class _QuotaMixin(_StoreBase):
    """Atomic multi-window reservations."""

    async def reserve_quota(
        self,
        windows: Sequence[tuple[str, int, int]],
    ) -> bool:
        """Reserve one call in every quota window, or refuse without spending.

        `windows` holds `(key, limit, ttl_ms)` tuples. The check and the
        increments happen in one Lua script, so two replicas can never both take
        the last free slot. A refused reservation leaves every counter
        untouched, which is what keeps a throttled provider from drifting over
        its published limits.

        Returns True when the call may be made.
        """
        if not windows:
            return True
        keys = [key for key, _limit, _ttl in windows]
        args: list[str] = []
        for _key, limit, ttl_ms in windows:
            args.extend([str(int(limit)), str(max(1, int(ttl_ms)))])
        granted = await self._run_script(self._reserve_quota_script, keys, args)
        return bool(granted)


__all__ = ["_QuotaMixin"]
