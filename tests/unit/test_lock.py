"""Distributed lock release must be atomic and ownership-aware."""

from __future__ import annotations

from opencanary_correlator.storage.redis_store import RedisStore


async def test_lock_release_removes_its_own_token(store) -> None:
    async with store.lock("lock") as acquired:
        assert acquired
        assert await store.get_value("lock") is not None

    assert await store.get_value("lock") is None


async def test_lock_release_preserves_a_new_owner(store) -> None:
    async with store.lock("lock") as acquired:
        assert acquired
        await store.set_value("lock", "new-owner")

    assert await store.get_value("lock") == "new-owner"


async def test_lock_release_with_a_stale_token_keeps_the_key(store) -> None:
    """A replica whose TTL expired must never delete the current owner's lock."""
    await store.set_value("lock", "current-owner")

    released = await store._release_lock("lock", "expired-token")

    assert released is False
    assert await store.get_value("lock") == "current-owner"


async def test_lock_release_is_a_single_script_call(store, fake_redis) -> None:
    """Compare-and-delete is one script, not WATCH/GET/MULTI/DEL/EXEC."""
    calls: list[str] = []
    original_evalsha = fake_redis.evalsha

    async def counting_evalsha(*args: object, **kwargs: object) -> object:
        calls.append("evalsha")
        return await original_evalsha(*args, **kwargs)  # type: ignore[arg-type]

    fake_redis.evalsha = counting_evalsha  # type: ignore[method-assign]
    racing_store = RedisStore(fake_redis)

    async def take_and_release() -> None:
        async with racing_store.lock("lock") as acquired:
            assert acquired

    # The first call also loads the script (EVALSHA -> NOSCRIPT -> SCRIPT LOAD).
    await take_and_release()
    calls.clear()

    await take_and_release()

    assert calls == ["evalsha"]
