"""Lua scripts executed atomically by :class:`RedisStore`.

Each script runs as one Redis round trip, so the multi-key writes they perform
cannot be interleaved with another replica's writes. The bodies are part of
the storage contract; change them only together with their tests.
"""

from __future__ import annotations

#: Release a lock only while it still holds our token, in one round trip.
#: A GET followed by DEL is racy (a TTL expiry in between would delete the new
#: owner's lock); WATCH does the same job in five commands per event.
RELEASE_LOCK_LUA = """
if redis.call('GET', KEYS[1]) == ARGV[1] then
    return redis.call('DEL', KEYS[1])
end
return 0
"""

#: Write the incident hash, its index entry and the per-host pointer atomically.
#: MULTI would need five commands per incident; one script does the same work in
#: one round trip. ARGV[1] is the score, ARGV[2] the pointer value, and the
#: remaining arguments are the hash field/value pairs.
SAVE_INCIDENT_LUA = """
redis.call('HSET', KEYS[1], unpack(ARGV, 3))
redis.call('ZADD', KEYS[2], ARGV[1], KEYS[1])
if KEYS[3] then
    redis.call('HSET', KEYS[3], 'key', ARGV[2], 'score', ARGV[1])
end
return 1
"""

#: Reserve one call in every configured quota window, or refuse without
#: spending anything. ARGV is `limit, ttl_ms` pairs, one per key. Checking and
#: incrementing separately would let two replicas both pass the check on the
#: last free slot, so the whole decision is one atomic script.
RESERVE_QUOTA_LUA = """
for i = 1, #KEYS do
    local limit = tonumber(ARGV[(i - 1) * 2 + 1])
    local current = tonumber(redis.call('GET', KEYS[i]) or '0')
    if current >= limit then
        return 0
    end
end
for i = 1, #KEYS do
    local ttl = tonumber(ARGV[(i - 1) * 2 + 2])
    local value = redis.call('INCR', KEYS[i])
    if value == 1 then
        redis.call('PEXPIRE', KEYS[i], ttl)
    end
end
return 1
"""

#: Write the incident and one pending delivery per channel in one round trip.
#: ARGV[1] score, ARGV[2] pointer value, ARGV[3] entry key prefix, ARGV[4]
#: comma-separated channels, ARGV[5..] hash field/value pairs. KEYS[4] is the
#: outbox index. Doing this in one script is the whole point: an incident that
#: exists without its pending deliveries is an alert that was decided on and
#: then lost.
SAVE_INCIDENT_WITH_ALERTS_LUA = """
redis.call('HSET', KEYS[1], unpack(ARGV, 5))
redis.call('ZADD', KEYS[2], ARGV[1], KEYS[1])
if KEYS[3] ~= '' then
    redis.call('HSET', KEYS[3], 'key', ARGV[2], 'score', ARGV[1])
end
if ARGV[4] ~= '' then
    for channel in string.gmatch(ARGV[4], '[^,]+') do
        local id = KEYS[1] .. '#' .. channel
        local entry = ARGV[3] .. id
        redis.call('HSET', entry, 'incident', KEYS[1], 'channel', channel,
                   'attempts', '0', 'created', ARGV[1])
        redis.call('ZADD', KEYS[4], ARGV[1], id)
    end
end
return 1
"""

#: Hand out the deliveries that are due, pushing each one's score forward by the
#: lease. The read and the reschedule happen together, so two replicas can never
#: claim the same entry; a worker that dies mid-delivery simply lets its lease
#: expire and the entry becomes due again.
CLAIM_DUE_ALERTS_LUA = """
local ids = redis.call('ZRANGEBYSCORE', KEYS[1], '-inf', ARGV[1], 'LIMIT', 0, tonumber(ARGV[2]))
for i = 1, #ids do
    redis.call('ZADD', KEYS[1], tonumber(ARGV[1]) + tonumber(ARGV[3]), ids[i])
end
return ids
"""

#: Record a delivery as done and drop its entry, but only if the entry still
#: exists. Returns 1 when this call settled it, 0 when there was nothing left
#: (already delivered by another replica, or never enqueued).
SETTLE_ALERT_LUA = """
if redis.call('EXISTS', KEYS[1]) == 0 then
    return 0
end
redis.call('SET', KEYS[2], '1', 'EX', ARGV[2])
redis.call('DEL', KEYS[1])
redis.call('ZREM', KEYS[3], ARGV[1])
return 1
"""

#: Turn a short dedup lease into a real window, but only while the key still holds
#: our token. A GET-then-PEXPIRE pair is racy: a lease expiring in between would
#: extend a claim another replica has since taken over.
CONFIRM_DEDUP_LUA = """
if redis.call('GET', KEYS[1]) == ARGV[1] then
    return redis.call('PEXPIRE', KEYS[1], ARGV[2])
end
return 0
"""

#: Admit one service message per `(kind, subject)` per cooldown, and count the
#: ones it turned away. ARGV[1] is the cooldown in seconds; KEYS[1] the
#: suppression slot, KEYS[2] the repeat counter. Taking the slot and reading the
#: counter in one script means a broken key cannot fail on every alert, and two
#: replicas cannot both report the same degradation.
SERVICE_MESSAGE_SLOT_LUA = """
if redis.call('SET', KEYS[1], '1', 'NX', 'EX', ARGV[1]) then
    local repeats = tonumber(redis.call('GET', KEYS[2]) or '0')
    if repeats > 0 then
        redis.call('DEL', KEYS[2])
    end
    return {1, repeats}
end
redis.call('INCR', KEYS[2])
redis.call('EXPIRE', KEYS[2], ARGV[1])
return {0, 0}
"""

#: Reserve one notification from the per-node and the global budget, or record a
#: suppression. Reserving and counting separately would let two replicas both use
#: the last free slot, and a suppression counted outside the reservation could be
#: lost between the two calls. ARGV: per-node limit, global limit, ttl_ms, node id,
#: summary due score. KEYS: node counter, global counter, summary hash, summary
#: index. A suppression re-adds the same summary member with the same score, so
#: the hundredth refused alert still schedules one summary.
RESERVE_ALERT_BUDGET_LUA = """
local node = tonumber(redis.call('GET', KEYS[1]) or '0')
local global = tonumber(redis.call('GET', KEYS[2]) or '0')
if node < tonumber(ARGV[1]) and global < tonumber(ARGV[2]) then
    if redis.call('INCR', KEYS[1]) == 1 then
        redis.call('PEXPIRE', KEYS[1], ARGV[3])
    end
    if redis.call('INCR', KEYS[2]) == 1 then
        redis.call('PEXPIRE', KEYS[2], ARGV[3])
    end
    return 1
end
redis.call('HINCRBY', KEYS[3], ARGV[4], 1)
redis.call('PEXPIRE', KEYS[3], ARGV[3])
redis.call('ZADD', KEYS[4], ARGV[5], KEYS[3])
return 0
"""

#: Hand one closed-window summary to exactly one worker. Removing it before the
#: read is what makes the handover exclusive: every replica runs this loop, and a
#: read-then-remove pair would let two of them send the same summary.
TAKE_BUDGET_SUMMARY_LUA = """
if redis.call('ZREM', KEYS[1], ARGV[1]) == 0 then
    return {}
end
local flat = redis.call('HGETALL', KEYS[2])
redis.call('DEL', KEYS[2])
return flat
"""

#: Drop pending deliveries nobody will attempt, one batch at a time. ARGV[i] is
#: the index member for KEYS[i + 1]. A suppressed alert must not keep its outbox
#: entry: the worker would deliver it later and the ration would be a delay
#: rather than a limit.
DISCARD_ALERTS_LUA = """
local removed = 0
for i = 2, #KEYS do
    removed = removed + redis.call('DEL', KEYS[i])
    redis.call('ZREM', KEYS[1], ARGV[i - 1])
end
return removed
"""

__all__ = [
    "CLAIM_DUE_ALERTS_LUA",
    "CONFIRM_DEDUP_LUA",
    "DISCARD_ALERTS_LUA",
    "RELEASE_LOCK_LUA",
    "RESERVE_ALERT_BUDGET_LUA",
    "RESERVE_QUOTA_LUA",
    "SAVE_INCIDENT_LUA",
    "SAVE_INCIDENT_WITH_ALERTS_LUA",
    "SERVICE_MESSAGE_SLOT_LUA",
    "SETTLE_ALERT_LUA",
    "TAKE_BUDGET_SUMMARY_LUA",
]
