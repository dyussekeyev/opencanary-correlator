"""Plain string values: the enrichment cache and small flags."""

from __future__ import annotations

from typing import cast

from redis.commands.core import Script

from opencanary_correlator.storage._base import _StoreBase

_EXTEND_TTL_LUA = """
local ttl = redis.call('PTTL', KEYS[1])
if ttl < tonumber(ARGV[2]) then
    redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
    return 1
end
return 0
"""


class _CacheMixin(_StoreBase):
    """String reads and writes."""

    async def extend_cached_value(self, key: str, value: str, *, ttl: float) -> bool:
        """Atomically install a TTL value without shortening an existing pause."""
        script = cast(Script, self._client.register_script(_EXTEND_TTL_LUA))
        return bool(await self._run_script(script, [key], [value, str(max(1, int(ttl * 1000)))]))

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
