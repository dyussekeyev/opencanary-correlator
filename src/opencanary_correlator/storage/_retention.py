"""Bounded, opt-in removal of old incidents and dead-letter deliveries.

Deletion is the one place where a bug is not recoverable, so every decision is
made in one script and in the safe direction: an incident is kept when anything
about it is still owed (a preparation, a queued target, a dead letter waiting for
inspection) and the caller is told which of the two happened. Nothing here runs
unless an operator enables retention, and nothing touches a live delivery.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import cast

from redis.commands.core import Script

from opencanary_correlator.constants import KEY_INCIDENTS
from opencanary_correlator.storage._base import _StoreBase
from opencanary_correlator.storage.keys import (
    INCIDENTS_CREATED,
    OUTBOX_DEAD,
    OUTBOX_ENTRY_PREFIX,
    OUTBOX_INDEX,
    outbox_alert_key,
    outbox_envelope_key,
)

#: Delete one incident only when nothing still owes a delivery for it.
#: Returns 1 (deleted), 0 (already gone; the index member is cleaned) or
#: -1 (kept: a preparation, queued target or dead letter still references it).
_EXPIRE_INCIDENT = """
if redis.call('EXISTS', KEYS[1]) == 0 then
    redis.call('ZREM', KEYS[2], ARGV[1])
    return 0
end
if redis.call('HGET', KEYS[3], 'state') == 'preparing' then return -1 end
local targets = redis.call('HGET', KEYS[3], 'targets') or ''
for target in string.gmatch(targets, '[^,]+') do
    local id = ARGV[1] .. '#' .. target
    if redis.call('ZSCORE', KEYS[4], id) or redis.call('ZSCORE', KEYS[5], id) then return -1 end
end
redis.call('DEL', KEYS[1], KEYS[3])
redis.call('ZREM', KEYS[2], ARGV[1])
redis.call('ZREM', KEYS[7], ARGV[1])
if KEYS[6] ~= '' and redis.call('HGET', KEYS[6], 'key') == ARGV[1] then
    redis.call('DEL', KEYS[6])
end
return 1
"""

#: Remove one dead letter that is older than the operator's DLQ retention.
_EXPIRE_DEAD = """
local score = redis.call('ZSCORE', KEYS[1], ARGV[1])
if not score or tonumber(score) > tonumber(ARGV[2]) then return 0 end
local hash = KEYS[3] .. ARGV[1]
if redis.call('EXISTS', hash) == 1 then
    if redis.call('HGET', hash, 'state') ~= 'dead' then return 0 end
    redis.call('DEL', hash)
end
redis.call('ZREM', KEYS[1], ARGV[1])
return 1
"""

#: Put one dead letter back into the delivery index with fresh attempts.
_REPLAY_DEAD = """
if not redis.call('ZSCORE', KEYS[1], ARGV[1]) then return 0 end
local hash = KEYS[3] .. ARGV[1]
if redis.call('HGET', hash, 'state') ~= 'dead' then return 0 end
redis.call('HSET', hash, 'state', 'ready', 'attempts', '0', 'last_error', 'replayed',
           'expires', tonumber(ARGV[2]) + tonumber(ARGV[3]))
redis.call('HDEL', hash, 'owner', 'lease_until')
redis.call('ZREM', KEYS[1], ARGV[1])
redis.call('ZADD', KEYS[2], ARGV[2], ARGV[1])
return 1
"""


class _RetentionMixin(_StoreBase):
    """Sweep old incidents, expire dead letters and requeue one by hand."""

    async def _retention_script(
        self, body: str, keys: Sequence[str], args: Sequence[str]
    ) -> object:
        return await self._run_script(cast(Script, self._client.register_script(body)), keys, args)

    async def expire_incident(self, key: str, *, pointer_key: str = "") -> int:
        """Delete one incident and its traces, or report why it is kept.

        The pointer is deleted only while it still points at this incident, so a
        newer incident for the same source host never loses its shortcut.
        """
        result = await self._retention_script(
            _EXPIRE_INCIDENT,
            [
                key,
                KEY_INCIDENTS,
                outbox_envelope_key(key),
                OUTBOX_INDEX,
                OUTBOX_DEAD,
                pointer_key,
                INCIDENTS_CREATED,
            ],
            [key],
        )
        return 0 if not result else int(self._text(result))

    async def expire_dead_letter(self, entry_id: str, *, cutoff: float) -> bool:
        """Remove one dead letter older than `cutoff`, keeping a live one."""
        return bool(
            await self._retention_script(
                _EXPIRE_DEAD,
                [OUTBOX_DEAD, OUTBOX_INDEX, OUTBOX_ENTRY_PREFIX],
                [entry_id, str(cutoff)],
            )
        )

    async def replay_dead_letter(self, entry_id: str, *, now: float, retention: float) -> bool:
        """Requeue exactly one dead letter; a second call is a no-op."""
        return bool(
            await self._retention_script(
                _REPLAY_DEAD,
                [OUTBOX_DEAD, OUTBOX_INDEX, OUTBOX_ENTRY_PREFIX],
                [entry_id, str(now), str(max(60.0, retention))],
            )
        )

    async def prune_incident_creations(self, *, cutoff: float) -> int:
        """Drop creation times older than the digest window; the ZSET has no TTL.

        Without this, one member per incident accumulates forever, which is a
        slow leak in the very key the daily digest depends on.
        """
        return int(await self._client.zremrangebyscore(INCIDENTS_CREATED, "-inf", cutoff))

    async def dead_letters(self, *, limit: int) -> list[dict[str, str]]:
        """Read dead letters newest first, without changing anything.

        Only routing identity and the classifier's reason are returned: the
        stored payload may contain log data, so inspection never echoes it.
        """
        rows = await self._client.zrevrange(OUTBOX_DEAD, 0, max(0, int(limit)) - 1, withscores=True)
        entries: list[dict[str, str]] = []
        for raw_id, score in rows:
            entry_id = self._text(raw_id)
            fields = await self.hgetall(outbox_alert_key(entry_id))
            entries.append(
                {
                    "entry": entry_id,
                    "target": fields.get("target", ""),
                    "incident": fields.get("incident", ""),
                    "attempts": fields.get("attempts", ""),
                    "state": fields.get("state", ""),
                    "last_error": fields.get("last_error", ""),
                    "dead_since": str(int(float(score))),
                }
            )
        return entries


__all__ = ["_RetentionMixin"]
