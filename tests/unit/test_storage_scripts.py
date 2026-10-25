"""Direct tests for the atomic Lua scripts in ``storage.scripts``.

The scripts run inside fakeredis through its Lua engine, so the same bodies that
production Redis executes are exercised here.
"""

from __future__ import annotations

from typing import Any

from opencanary_correlator.storage.scripts import RELEASE_LOCK_LUA, SAVE_INCIDENT_LUA


async def test_release_lock_deletes_key_when_token_matches(fake_redis: Any) -> None:
    await fake_redis.set("lock:x", "token-a")

    released = await fake_redis.eval(RELEASE_LOCK_LUA, 1, "lock:x", "token-a")

    assert released == 1
    assert await fake_redis.exists("lock:x") == 0


async def test_release_lock_keeps_key_owned_by_someone_else(fake_redis: Any) -> None:
    await fake_redis.set("lock:x", "token-b")

    released = await fake_redis.eval(RELEASE_LOCK_LUA, 1, "lock:x", "token-a")

    assert released == 0
    assert await fake_redis.get("lock:x") == "token-b"


async def test_release_lock_on_missing_key_is_a_noop(fake_redis: Any) -> None:
    released = await fake_redis.eval(RELEASE_LOCK_LUA, 1, "lock:x", "token-a")

    assert released == 0
    assert await fake_redis.exists("lock:x") == 0


async def test_save_incident_writes_hash_index_and_host_pointer(fake_redis: Any) -> None:
    result = await fake_redis.eval(
        SAVE_INCIDENT_LUA,
        3,
        "incident:ftplogin:10.0.0.5:1",
        "incidents:index",
        "pointer:10.0.0.5",
        "1700000000",
        "incident:ftplogin:10.0.0.5:1",
        "node_id",
        "canary-1",
        "src_host",
        "10.0.0.5",
    )

    assert result == 1
    assert await fake_redis.hgetall("incident:ftplogin:10.0.0.5:1") == {
        "node_id": "canary-1",
        "src_host": "10.0.0.5",
    }
    assert await fake_redis.zscore("incidents:index", "incident:ftplogin:10.0.0.5:1") == 1700000000
    assert await fake_redis.hgetall("pointer:10.0.0.5") == {
        "key": "incident:ftplogin:10.0.0.5:1",
        "score": "1700000000",
    }


async def test_save_incident_without_pointer_key_skips_host_pointer(fake_redis: Any) -> None:
    result = await fake_redis.eval(
        SAVE_INCIDENT_LUA,
        2,
        "incident:scan:10.0.0.9:2",
        "incidents:index",
        "10",
        "incident:scan:10.0.0.9:2",
        "src_host",
        "10.0.0.9",
    )

    assert result == 1
    assert await fake_redis.hget("incident:scan:10.0.0.9:2", "src_host") == "10.0.0.9"
    assert await fake_redis.zscore("incidents:index", "incident:scan:10.0.0.9:2") == 10
    assert await fake_redis.keys("pointer:*") == []


async def test_save_incident_merges_fields_into_existing_hash(fake_redis: Any) -> None:
    await fake_redis.hset("incident:x:1", mapping={"keep": "yes", "count": "1"})

    await fake_redis.eval(
        SAVE_INCIDENT_LUA,
        2,
        "incident:x:1",
        "incidents:index",
        "5",
        "incident:x:1",
        "count",
        "2",
    )

    assert await fake_redis.hgetall("incident:x:1") == {"keep": "yes", "count": "2"}
