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

__all__ = ["RELEASE_LOCK_LUA", "SAVE_INCIDENT_LUA"]
