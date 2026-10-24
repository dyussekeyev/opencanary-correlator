"""Redis-backed rate limiter: budgets, windows, isolation and disabled limits."""

from __future__ import annotations

import asyncio

from opencanary_correlator.storage.rate_limit import RedisRateLimiter


async def test_event_budget_is_enforced_per_node(store) -> None:
    limiter = RedisRateLimiter(store, events_per_minute=2)

    assert await limiter.allow_event("canary-1") is True
    assert await limiter.allow_event("canary-1") is True
    assert await limiter.allow_event("canary-1") is False
    assert await limiter.allow_event("canary-2") is True


async def test_zero_budget_disables_event_limiting(store) -> None:
    limiter = RedisRateLimiter(store, events_per_minute=0)

    assert all([await limiter.allow_event("canary-1") for _ in range(5)])


async def test_connection_budget_is_tracked_separately(store) -> None:
    limiter = RedisRateLimiter(store, events_per_minute=100, connections_per_minute=1)

    assert await limiter.allow_connection("10.0.0.5") is True
    assert await limiter.allow_connection("10.0.0.5") is False
    assert await limiter.allow_connection("10.0.0.6") is True
    assert await limiter.allow_event("10.0.0.5") is True


async def test_zero_connection_budget_disables_the_check(store) -> None:
    limiter = RedisRateLimiter(store, events_per_minute=10, connections_per_minute=0)

    assert all([await limiter.allow_connection("10.0.0.5") for _ in range(5)])


async def test_window_resets_even_while_traffic_continues(store) -> None:
    """The window must expire on schedule instead of being extended by requests.

    With a refreshed TTL the denied request in the middle of the window would
    push the expiry out and the following request would still be rejected.
    """
    limiter = RedisRateLimiter(
        store,
        events_per_minute=2,
        connections_per_minute=1,
        window_seconds=2,
    )

    assert await limiter.allow_event("canary-1") is True
    assert await limiter.allow_event("canary-1") is True
    assert await limiter.allow_connection("10.0.0.5") is True

    await asyncio.sleep(1.1)

    assert await limiter.allow_event("canary-1") is False
    assert await limiter.allow_connection("10.0.0.5") is False

    await asyncio.sleep(1.1)

    assert await limiter.allow_event("canary-1") is True
    assert await limiter.allow_connection("10.0.0.5") is True
