"""Versioned outbox with atomic, lease-fenced state transitions.

No pending hash has a TTL: deadlines are processed explicitly into a terminal
state, so an index can never silently outlive its payload. All timestamps use
the same caller clock (wall time in production, controlled time in tests).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import cast
from uuid import uuid4

from redis.commands.core import Script

from opencanary_correlator.storage._base import _StoreBase
from opencanary_correlator.storage.keys import (
    BUDGET_SUMMARIES,
    OUTBOX_DEAD,
    OUTBOX_ENTRY_PREFIX,
    OUTBOX_INDEX,
    OUTBOX_PREPARING,
    budget_global_key,
    budget_node_key,
    budget_summary_key,
    delivered_key,
    outbox_alert_key,
    outbox_envelope_key,
)

# Claim just before working, never an entire sequential batch. Increment the
# attempt BEFORE I/O, including attempts interrupted by a process crash.
_CLAIM = """
local due = redis.call('ZSCORE', KEYS[1], ARGV[1])
if not due or tonumber(due) > tonumber(ARGV[2]) then return '' end
if redis.call('EXISTS', KEYS[2]) == 0 then
    redis.call('ZREM', KEYS[1], ARGV[1])
    redis.call('HSET', KEYS[2], 'state', 'dead', 'last_error', 'missing_entry')
    redis.call('ZADD', KEYS[3], ARGV[2], ARGV[1])
    return 'missing_entry'
end
local expires = tonumber(redis.call('HGET', KEYS[2], 'expires') or '0')
local attempts = tonumber(redis.call('HGET', KEYS[2], 'attempts') or '0')
local reason = ''
if not expires or not attempts or attempts < 0 or attempts % 1 ~= 0 then
    reason = 'corrupt_entry'
    expires = expires or 0
    attempts = attempts or 0
end
if ARGV[5] == 'delivery' then
    local state = redis.call('HGET', KEYS[2], 'state')
    if state ~= 'ready' and state ~= 'sending' then reason = 'corrupt_entry' end
    if not redis.call('HGET', KEYS[2], 'incident') or
       not redis.call('HGET', KEYS[2], 'target') then reason = 'corrupt_entry' end
end
if expires > 0 and expires <= tonumber(ARGV[2]) then reason = 'expired' end
if ARGV[5] == 'delivery' and attempts >= tonumber(ARGV[6]) then reason = 'attempts_exhausted' end
if reason ~= '' then
    redis.call('HSET', KEYS[2], 'state', 'dead', 'last_error', reason)
    redis.call('HDEL', KEYS[2], 'owner', 'lease_until')
    redis.call('ZREM', KEYS[1], ARGV[1])
    redis.call('ZADD', KEYS[3], ARGV[2], ARGV[1])
    if ARGV[5] == 'preparation' then
        for target in string.gmatch(redis.call('HGET', KEYS[2], 'targets') or '', '[^,]+') do
            local id = ARGV[1] .. '#' .. target
            redis.call('HSET', ARGV[7] .. id, 'state', 'dead', 'last_error', reason)
            redis.call('ZADD', KEYS[3], ARGV[2], id)
        end
    end
    return reason
end
local until_time = tonumber(ARGV[2]) + tonumber(ARGV[3])
redis.call('HSET', KEYS[2], 'owner', ARGV[4], 'lease_until', until_time)
if ARGV[5] == 'delivery' then
    redis.call('HINCRBY', KEYS[2], 'attempts', 1)
    redis.call('HSET', KEYS[2], 'state', 'sending')
end
redis.call('ZADD', KEYS[1], until_time, ARGV[1])
return ARGV[4]
"""

# Budget reservation and publishing ready targets form ONE commit. A crash
# before it spends nothing; after it, recovery sees the saved decision.
_PREPARE = """
if redis.call('HGET', KEYS[1], 'owner') ~= ARGV[1] or
   tonumber(redis.call('HGET', KEYS[1], 'lease_until') or '0') <= tonumber(ARGV[2]) then
    return ''
end
if redis.call('HGET', KEYS[1], 'state') ~= 'preparing' then return '' end
local allowed = true
local node = redis.call('HGET', KEYS[1], 'node_id') or ''
if ARGV[5] == '1' then
    local n = tonumber(redis.call('GET', KEYS[4]) or '0')
    local g = tonumber(redis.call('GET', KEYS[5]) or '0')
    allowed = n < tonumber(ARGV[6]) and g < tonumber(ARGV[7])
    if allowed then
        if redis.call('INCR', KEYS[4]) == 1 then redis.call('PEXPIRE', KEYS[4], ARGV[8]) end
        if redis.call('INCR', KEYS[5]) == 1 then redis.call('PEXPIRE', KEYS[5], ARGV[8]) end
    else
        redis.call('HINCRBY', KEYS[6], node, 1)
        redis.call('PEXPIRE', KEYS[6], ARGV[8])
        redis.call('ZADD', KEYS[7], ARGV[9], KEYS[6])
    end
end
local state = allowed and 'ready' or 'suppressed'
redis.call('HSET', KEYS[1], 'state', state, 'enrichment', ARGV[3], 'budget', state)
redis.call('HDEL', KEYS[1], 'owner', 'lease_until')
redis.call('ZREM', KEYS[2], ARGV[4])
local targets = redis.call('HGET', KEYS[1], 'targets') or ''
for target in string.gmatch(targets, '[^,]+') do
    local id = ARGV[4] .. '#' .. target
    local entry = ARGV[10] .. id
    if redis.call('HGET', entry, 'state') == 'preparing' then
        redis.call('HSET', entry, 'state', state)
        if allowed then redis.call('ZADD', KEYS[3], ARGV[2], id) end
    else
        -- Missing/corrupt target payload must be visible on the next claim.
        redis.call('ZADD', KEYS[3], ARGV[2], id)
    end
end
return state
"""

# Ownership AND a live lease are required for EVERY transition. No EXISTS/write
# gap, and no stale process can recreate a delivered or terminal hash.
_TRANSITION = """
if redis.call('HGET', KEYS[1], 'owner') ~= ARGV[1] or
   tonumber(redis.call('HGET', KEYS[1], 'lease_until') or '0') <= tonumber(ARGV[2]) then
    return 0
end
redis.call('HDEL', KEYS[1], 'owner', 'lease_until')
if ARGV[3] == 'delivered' then
    redis.call('SET', KEYS[4], '1', 'EX', ARGV[7])
    redis.call('DEL', KEYS[1])
    redis.call('ZREM', KEYS[2], ARGV[4])
elseif ARGV[3] == 'ready' then
    redis.call('HSET', KEYS[1], 'state', 'ready', 'last_error', ARGV[5])
    redis.call('ZADD', KEYS[2], ARGV[6], ARGV[4])
else
    redis.call('HSET', KEYS[1], 'state', 'dead', 'last_error', ARGV[5])
    redis.call('PERSIST', KEYS[1])
    redis.call('ZREM', KEYS[2], ARGV[4])
    redis.call('ZADD', KEYS[3], ARGV[2], ARGV[4])
end
return 1
"""


class _OutboxMixin(_StoreBase):
    """Preparation, one-at-a-time claims and fenced settlement."""

    async def _outbox_script(self, body: str, keys: Sequence[str], args: Sequence[str]) -> object:
        return await self._run_script(cast(Script, self._client.register_script(body)), keys, args)

    async def enqueue_alert(
        self,
        entry_id: str,
        *,
        incident_key: str,
        channel: str,
        score: float,
        retention: float = 604800,
    ) -> None:
        """Enqueue an already-decided repair delivery (not normal ingestion)."""
        async with self._client.pipeline(transaction=True) as pipe:
            pipe.hset(
                outbox_alert_key(entry_id),
                mapping={
                    "incident": incident_key,
                    "channel": channel.split(":", 1)[0],
                    "target": channel,
                    "attempts": "0",
                    "created": str(score),
                    "expires": str(score + retention),
                    "state": "ready",
                },
            )
            pipe.zadd(OUTBOX_INDEX, {entry_id: score})
            await pipe.execute()

    async def enqueue_notice(
        self,
        occurrence: str,
        payload: str,
        targets: Sequence[str],
        *,
        now: float,
        retention: float,
        marker: str = "",
        marker_ttl: int = 604800,
        mute: str = "",
        repeats: str = "",
        source_summary: str = "",
    ) -> bool:
        """Atomic occurrence admission, immutable payload and per-target debts.

        Suppression/marker and source summary acknowledgement commit with debts,
        never before them. Existing occurrence cannot be rerouted or resurrected.
        """
        body = """
if KEYS[4] ~= '' and redis.call('EXISTS', KEYS[4]) == 1 then return 0 end
if KEYS[5] ~= '' and redis.call('EXISTS', KEYS[5]) == 1 then
    redis.call('INCR', KEYS[6]); redis.call('EXPIRE', KEYS[6], ARGV[6]); return 0
end
if redis.call('EXISTS', KEYS[1]) == 1 then return 0 end
if KEYS[7] ~= '' and redis.call('ZSCORE', KEYS[8], KEYS[7]) == false then return 0 end
redis.call('HSET', KEYS[1], 'state', 'ready', 'kind', 'notice', 'payload', ARGV[2])
for target in string.gmatch(ARGV[3], '[^,]+') do
    local id = ARGV[1] .. '#' .. target
    redis.call('HSET', ARGV[5] .. id, 'incident', ARGV[1], 'target', target,
        'state', 'ready', 'attempts', '0', 'created', ARGV[4],
        'expires', tonumber(ARGV[4]) + tonumber(ARGV[7]))
    redis.call('ZADD', KEYS[2], ARGV[4], id)
end
if KEYS[4] ~= '' then redis.call('SET', KEYS[4], '1', 'EX', ARGV[6]) end
if KEYS[5] ~= '' then
    redis.call('SET', KEYS[5], '1', 'EX', ARGV[6]); redis.call('DEL', KEYS[6])
end
if KEYS[7] ~= '' then
    redis.call('ZREM', KEYS[8], KEYS[7]); redis.call('DEL', KEYS[7])
end
return 1
"""
        if not targets:
            return False
        return bool(
            await self._outbox_script(
                body,
                [
                    outbox_envelope_key(occurrence),
                    OUTBOX_INDEX,
                    OUTBOX_DEAD,
                    marker,
                    mute,
                    repeats,
                    source_summary,
                    BUDGET_SUMMARIES,
                ],
                [
                    occurrence,
                    payload,
                    ",".join(targets),
                    str(now),
                    OUTBOX_ENTRY_PREFIX,
                    str(max(1, marker_ttl)),
                    str(retention),
                ],
            )
        )

    async def due_alerts(self, *, now: float, limit: int, preparing: bool = False) -> list[str]:
        index = OUTBOX_PREPARING if preparing else OUTBOX_INDEX
        values = await self._client.zrangebyscore(index, "-inf", now, start=0, num=limit)
        return [self._text(value) for value in values]

    async def claim_alert(
        self,
        entry_id: str,
        *,
        now: float,
        lease: float,
        max_attempts: int,
        preparing: bool = False,
    ) -> str:
        """Return an owner token, empty if busy, or a terminal reason."""
        token = uuid4().hex
        result = await self._outbox_script(
            _CLAIM,
            [
                OUTBOX_PREPARING if preparing else OUTBOX_INDEX,
                outbox_envelope_key(entry_id) if preparing else outbox_alert_key(entry_id),
                OUTBOX_DEAD,
            ],
            [
                entry_id,
                str(now),
                str(lease),
                token,
                "preparation" if preparing else "delivery",
                str(max_attempts),
                OUTBOX_ENTRY_PREFIX,
            ],
        )
        return self._text(result) if result else ""

    async def prepare_alerts(
        self,
        incident_key: str,
        *,
        owner: str,
        now: float,
        enrichment: str,
        budget_enabled: bool,
        node_id: str,
        window: float,
        per_node: int,
        global_limit: int,
    ) -> str:
        stamp = int(now - now % window)
        result = await self._outbox_script(
            _PREPARE,
            [
                outbox_envelope_key(incident_key),
                OUTBOX_PREPARING,
                OUTBOX_INDEX,
                budget_node_key(stamp, node_id),
                budget_global_key(stamp),
                budget_summary_key(stamp),
                BUDGET_SUMMARIES,
            ],
            [
                owner,
                str(now),
                enrichment,
                incident_key,
                "1" if budget_enabled else "0",
                str(per_node),
                str(global_limit),
                str(max(60000, int(window * 2000))),
                str(stamp + window),
                OUTBOX_ENTRY_PREFIX,
            ],
        )
        return self._text(result) if result else ""

    async def owns_alert(self, entry_id: str, *, owner: str, now: float) -> bool:
        """Recheck after payload reads, before starting external I/O."""
        body = """
return redis.call('HGET', KEYS[1], 'owner') == ARGV[1] and
       tonumber(redis.call('HGET', KEYS[1], 'lease_until') or '0') > tonumber(ARGV[2])
"""
        return bool(
            await self._outbox_script(body, [outbox_alert_key(entry_id)], [owner, str(now)])
        )

    async def read_alert(self, entry_id: str) -> dict[str, str] | None:
        return await self.hgetall(outbox_alert_key(entry_id)) or None

    async def transition_alert(
        self,
        entry_id: str,
        *,
        owner: str,
        now: float,
        state: str,
        error: str = "",
        next_attempt: float = 0,
        retention: float = 604800,
    ) -> bool:
        if state not in {"ready", "delivered", "dead"}:
            raise ValueError("invalid outbox transition")
        result = await self._outbox_script(
            _TRANSITION,
            [
                outbox_alert_key(entry_id),
                OUTBOX_INDEX,
                OUTBOX_DEAD,
                delivered_key(entry_id),
            ],
            [
                owner,
                str(now),
                state,
                entry_id,
                error[:200],
                str(next_attempt),
                str(max(1, int(retention))),
            ],
        )
        return bool(result)

    async def fail_alert_preparation(
        self,
        incident_key: str,
        *,
        owner: str,
        now: float,
        reason: str,
    ) -> bool:
        body = """
if redis.call('HGET', KEYS[1], 'owner') ~= ARGV[1] or
   tonumber(redis.call('HGET', KEYS[1], 'lease_until') or '0') <= tonumber(ARGV[2]) then
    return 0
end
redis.call('HSET', KEYS[1], 'state', 'dead', 'last_error', ARGV[3])
redis.call('HDEL', KEYS[1], 'owner', 'lease_until')
redis.call('ZREM', KEYS[2], ARGV[4])
for target in string.gmatch(redis.call('HGET', KEYS[1], 'targets') or '', '[^,]+') do
    local id = ARGV[4] .. '#' .. target
    redis.call('HSET', ARGV[5] .. id, 'state', 'dead', 'last_error', ARGV[3])
    redis.call('ZADD', KEYS[3], ARGV[2], id)
end
return 1
"""
        return bool(
            await self._outbox_script(
                body,
                [outbox_envelope_key(incident_key), OUTBOX_PREPARING, OUTBOX_DEAD],
                [owner, str(now), reason, incident_key, OUTBOX_ENTRY_PREFIX],
            )
        )

    async def outbox_pending(self) -> int:
        """Runnable/in-flight target debts, not undecided preparations."""
        return int(await self._client.zcard(OUTBOX_INDEX))

    async def outbox_stats(self) -> tuple[int, int, float | None]:
        """Pending count, dead count and the oldest pending next-attempt score.

        One pipeline, because three separate calls would sample three different
        moments while deliveries settle in between.
        """
        async with self._client.pipeline(transaction=False) as pipe:
            pipe.zcard(OUTBOX_INDEX)
            pipe.zcard(OUTBOX_DEAD)
            pipe.zrange(OUTBOX_INDEX, 0, 0, withscores=True)
            pending, dead, first = await pipe.execute()
        oldest = float(first[0][1]) if first else None
        return int(pending), int(dead), oldest

    async def outbox_dead(self) -> int:
        return int(await self._client.zcard(OUTBOX_DEAD))


__all__ = ["_OutboxMixin"]
