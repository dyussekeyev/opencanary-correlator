"""A store on a bytes-returning client must read like the production one.

`RedisStore.from_url` always builds a client with `decode_responses=True`, but
`RedisStore(client)` accepts whatever the caller passes. A bytes client used to
make every string read answer `None` (the enrichment cache silently missed) and
made `hgetall`/`smembers`/`lrange` answer `"b'...'"`. These tests pin the
normalisation so the two clients stay interchangeable.
"""

from __future__ import annotations

import fakeredis.aioredis
import pytest


@pytest.fixture
def bytes_store() -> object:
    from opencanary_correlator.storage.redis_store import RedisStore

    return RedisStore(fakeredis.aioredis.FakeRedis(decode_responses=False))


async def test_string_values_survive_a_bytes_client(bytes_store: object) -> None:
    from opencanary_correlator.storage.redis_store import RedisStore

    store = bytes_store
    assert isinstance(store, RedisStore)

    await store.set_value("cache:key", "cached-value")

    assert await store.get_value("cache:key") == "cached-value"
    assert await store.get_value("absent") is None


async def test_hash_set_and_list_reads_are_text(bytes_store: object) -> None:
    from opencanary_correlator.storage.redis_store import RedisStore

    store = bytes_store
    assert isinstance(store, RedisStore)

    await store.hset_mapping("incident:1", {"src_host": "10.0.0.5"})
    await store.client.sadd("scan:1", "22")
    await store.client.zadd("index:1", {"member": 1})
    await store.lpush_trim("log:1", "a line", max_entries=10)

    assert await store.hgetall("incident:1") == {"src_host": "10.0.0.5"}
    assert await store.hget("incident:1", "src_host") == "10.0.0.5"
    assert await store.smembers("scan:1") == {"22"}
    assert await store.zrangebyscore("index:1", "-inf", "+inf") == ["member"]
    assert await store.zrevrangebyscore("index:1", "+inf", "-inf") == ["member"]
    assert await store.lrange("log:1") == ["a line"]
