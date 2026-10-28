"""The client a URL builds must fail a command, not wait forever.

A Redis that accepts the connection and then stops answering is the one failure
mode the correlator cannot recover from on its own: ingest, the health probe and
every dispatch share one event loop, so a single unanswered command stalls the
whole process with nothing in the log. These tests pin the timeouts that turn
that into an auditable error.
"""

from __future__ import annotations

from opencanary_correlator.storage._base import (
    DEFAULT_HEALTH_CHECK_INTERVAL_SECONDS,
    DEFAULT_SOCKET_CONNECT_TIMEOUT_SECONDS,
    DEFAULT_SOCKET_TIMEOUT_SECONDS,
)
from opencanary_correlator.storage.redis_store import RedisStore


def connection_kwargs(store: RedisStore) -> dict[str, object]:
    """Return the kwargs the pool passes to every connection."""
    return dict(store.client.connection_pool.connection_kwargs)


def test_a_store_from_a_url_always_sets_the_timeouts() -> None:
    store = RedisStore.from_url("redis://localhost:6379/0")

    kwargs = connection_kwargs(store)

    assert kwargs["socket_timeout"] == DEFAULT_SOCKET_TIMEOUT_SECONDS
    assert kwargs["socket_connect_timeout"] == DEFAULT_SOCKET_CONNECT_TIMEOUT_SECONDS
    assert kwargs["health_check_interval"] == DEFAULT_HEALTH_CHECK_INTERVAL_SECONDS
    assert kwargs["decode_responses"] is True


def test_the_timeouts_can_be_overridden_per_store() -> None:
    """A tool that deliberately holds a long blocking command needs its own value."""
    store = RedisStore.from_url(
        "redis://localhost:6379/0",
        socket_timeout=30.0,
        socket_connect_timeout=2.0,
        health_check_interval=0,
    )

    kwargs = connection_kwargs(store)

    assert kwargs["socket_timeout"] == 30.0
    assert kwargs["socket_connect_timeout"] == 2.0
    assert kwargs["health_check_interval"] == 0
