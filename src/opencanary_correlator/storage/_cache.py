"""Plain string values: the enrichment cache and small flags."""

from __future__ import annotations

from opencanary_correlator.storage._base import _StoreBase


class _CacheMixin(_StoreBase):
    """String reads and writes."""

    async def get_value(self, key: str) -> str | None:
        """Read a string key.

        The reply is normalised, so a client built with
        ``decode_responses=False`` returns the value instead of ``None``.
        """
        value = await self._client.get(key)
        return None if value is None else self._text(value)

    async def set_value(self, key: str, value: str) -> None:
        """Write a string key."""
        await self._client.set(key, value)

    async def set_with_ttl(self, key: str, value: str, *, ttl: float) -> None:
        """Write a string key that expires after `ttl` seconds."""
        await self._client.set(key, value, px=max(1, int(ttl * 1000)))


__all__ = ["_CacheMixin"]
