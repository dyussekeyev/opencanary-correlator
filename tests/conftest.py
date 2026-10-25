"""Shared pytest fixtures for the correlator test suite."""

from __future__ import annotations

import json
import socket
from collections.abc import AsyncIterator, Callable
from typing import Any

import fakeredis.aioredis
import pytest
from redis.asyncio import Redis

from opencanary_correlator.config import Settings
from opencanary_correlator.core.incident import IncidentFTPLogin
from opencanary_correlator.storage.redis_store import RedisStore

TEST_REDIS_URL = "redis://localhost:6379/0"


def _find_free_port() -> int:
    """Ask the OS for a currently unused TCP port on the loopback interface."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture
def free_tcp_port() -> int:
    """Return a TCP port that was free a moment ago on the loopback interface."""
    return _find_free_port()


@pytest.fixture
async def fake_redis() -> AsyncIterator[Redis]:
    """Provide an isolated in-memory Redis substitute for a single test."""
    client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    try:
        yield client
    finally:
        await client.aclose()


@pytest.fixture
def store(fake_redis: Any) -> RedisStore:
    """Async store backed by fakeredis."""
    return RedisStore(fake_redis)


@pytest.fixture
def incident_factory() -> Callable[..., IncidentFTPLogin]:
    """Build persisted-looking incidents for dispatcher tests."""

    def _build(incident_cls: Any = IncidentFTPLogin, **overrides: Any) -> Any:
        params: dict[str, Any] = {
            "key": "incident:ftplogin:10.0.0.5:1418997029",
            "node_id": "canary-1",
            "src_host": "10.0.0.5",
            "src_port": 40000,
            "dst_host": "10.0.0.2",
            "dst_port": 21,
            "logtype": 2000,
            "created": 1418997029,
            "events_list": "1418997029",
            "events_count": 1,
            "logdata": json.dumps([{"USERNAME": "admin"}]),
        }
        params.update(overrides)
        return incident_cls(**params)

    return _build


@pytest.fixture
def settings_factory() -> Callable[..., Settings]:
    """Build settings without reading a developer's `.env` file."""

    def _build(**overrides: Any) -> Settings:
        params: dict[str, Any] = {"redis_url": TEST_REDIS_URL, "_env_file": None}
        params.update(overrides)
        return Settings(**params)

    return _build


@pytest.fixture
def event_factory() -> Callable[..., dict[str, Any]]:
    """Build raw OpenCanary events shaped like the output of `sanitizeLog()`."""

    def _build(**overrides: Any) -> dict[str, Any]:
        event: dict[str, Any] = {
            "src_host": "10.0.0.5",
            "src_port": 4444,
            "dst_host": "10.0.0.2",
            "dst_port": 21,
            "logtype": 2000,
            "node_id": "canary-1",
            "local_time": "2026-10-24 10:00:00.000000",
            "utc_time": "2026-10-24 10:00:00.000000",
            "local_time_adjusted": "2026-10-24 10:00:00.000000",
            "logdata": {"USERNAME": "admin", "PASSWORD": "hunter2"},
        }
        event.update(overrides)
        return event

    return _build


@pytest.fixture
def event_line(event_factory: Any) -> Callable[..., bytes]:
    """Serialise an event exactly like `SocketJSONHandler.makePickle()` does."""

    def _line(**overrides: Any) -> bytes:
        payload = json.dumps(event_factory(**overrides), sort_keys=True)
        return (payload + "\n").encode("utf-8")

    return _line
