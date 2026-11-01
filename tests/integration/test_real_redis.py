"""Opt-in checks against a real Redis server.

These tests are skipped unless ``OCC_TEST_REDIS_URL`` points at a **disposable**
database, for example ``redis://localhost:6379/15``. They exist because the rest
of the suite runs on fakeredis; this is the bridge to a real deployment.

    OCC_TEST_REDIS_URL=redis://localhost:6379/15 pytest tests/integration/test_real_redis.py

The tests namespace every key they create by a random source host and delete
only those keys afterwards, but a scratch database is still recommended.
"""

from __future__ import annotations

import asyncio
import io
import ipaddress
import json
import os
import signal
import sys
import uuid
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
from redis.asyncio import Redis

from opencanary_correlator.audit import AuditLogger
from opencanary_correlator.config import Settings
from opencanary_correlator.connectors.base import BaseDispatcher, DispatchResult, IncidentLike
from opencanary_correlator.constants import KEY_INCIDENTS
from opencanary_correlator.core.engine import CorrelationEngine
from opencanary_correlator.core.incident import Incident, IncidentRepository
from opencanary_correlator.core.rules import build_rules
from opencanary_correlator.core.windows import DedupCache
from opencanary_correlator.enrichment.virustotal import VirusTotalClient
from opencanary_correlator.schemas import CanaryEvent
from opencanary_correlator.storage import keys
from opencanary_correlator.storage.redis_store import RedisStore

REDIS_URL = os.environ.get("OCC_TEST_REDIS_URL", "").strip()

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not REDIS_URL,
        reason="set OCC_TEST_REDIS_URL to a disposable Redis database",
    ),
]


class RecordingDispatcher(BaseDispatcher):
    """Dispatcher collecting incidents in memory."""

    name = "recording"

    def __init__(self) -> None:
        self.incidents: list[Incident] = []

    async def dispatch(self, incident: IncidentLike) -> DispatchResult:
        assert isinstance(incident, Incident)
        self.incidents.append(incident)
        return DispatchResult(dispatcher=self.name, status="success")


def make_engine(
    store: RedisStore,
    settings: Settings,
    dispatcher: BaseDispatcher,
    audit: AuditLogger,
) -> CorrelationEngine:
    """Build an engine wired to one store, as the CLI does."""
    repository = IncidentRepository(store, settings, audit)
    return CorrelationEngine(
        rules=build_rules(store, repository, settings),
        dispatchers=[dispatcher],
        dedup=DedupCache(store, ttl=settings.dedup_ttl, lease=settings.dedup_lease),
        settings=settings,
        audit=audit,
    )


async def cleanup_host(store: RedisStore, src_host: str) -> None:
    """Delete the incident keys created for one test host."""
    needle = f":{src_host}:"
    for key in await store.zrangebyscore(KEY_INCIDENTS, "-inf", "+inf"):
        if needle in key:
            await store.delete(key)
            await store.client.zrem(KEY_INCIDENTS, key)


@pytest.fixture
async def real_settings(settings_factory: Any) -> Settings:
    """Settings pointing at the disposable database from the environment."""
    settings: Settings = settings_factory(
        redis_url=REDIS_URL,
        syslog_enabled=False,
        health_port=None,
        rate_limit_events_per_minute=0,
    )
    return settings


@pytest.fixture
async def replica_stores() -> AsyncIterator[list[RedisStore]]:
    """Two independent connections, standing in for two replicas."""
    clients = [Redis.from_url(REDIS_URL, decode_responses=True) for _ in range(2)]
    stores = [RedisStore(client) for client in clients]
    try:
        for store in stores:
            if not await store.ping():
                pytest.skip("Redis from OCC_TEST_REDIS_URL is not reachable")
        yield stores
    finally:
        for client in clients:
            await client.aclose()


async def test_duplicate_events_notify_once_across_replicas(
    replica_stores: Any, real_settings: Any, event_factory: Any
) -> None:
    src_host = f"198.51.100.{uuid.uuid4().int % 250 + 1}"
    dispatchers = [RecordingDispatcher(), RecordingDispatcher()]
    engines = [
        make_engine(store, real_settings, dispatcher, AuditLogger("test", stream=io.StringIO()))
        for store, dispatcher in zip(replica_stores, dispatchers, strict=True)
    ]
    event = CanaryEvent.model_validate(event_factory(src_host=src_host))
    try:
        await asyncio.gather(*(engine.handle_event(event) for engine in engines for _ in range(25)))

        incidents = await replica_stores[0].zrangebyscore(KEY_INCIDENTS, "-inf", "+inf")
        keys = [key for key in incidents if f":{src_host}:" in key]
        assert len(keys) == 1
        fields = await replica_stores[0].hgetall(keys[0])
        assert fields["events_count"] == "1"
        delivered = sum(len(dispatcher.incidents) for dispatcher in dispatchers)
        assert delivered == 1
    finally:
        await cleanup_host(replica_stores[0], src_host)


async def test_distinct_events_merge_into_one_incident(
    replica_stores: Any, real_settings: Any, event_factory: Any
) -> None:
    src_host = f"203.0.113.{uuid.uuid4().int % 250 + 1}"
    dispatchers = [RecordingDispatcher(), RecordingDispatcher()]
    engines = [
        make_engine(store, real_settings, dispatcher, AuditLogger("test", stream=io.StringIO()))
        for store, dispatcher in zip(replica_stores, dispatchers, strict=True)
    ]
    events = [
        CanaryEvent.model_validate(event_factory(src_host=src_host, src_port=41000 + index))
        for index in range(20)
    ]
    try:
        await asyncio.gather(
            *(engines[index % 2].handle_event(event) for index, event in enumerate(events))
        )

        incidents = await replica_stores[0].zrangebyscore(KEY_INCIDENTS, "-inf", "+inf")
        keys = [key for key in incidents if f":{src_host}:" in key]
        assert len(keys) == 1
        fields = await replica_stores[0].hgetall(keys[0])
        assert fields["events_count"] == "20"
        assert len(fields["events_list"].split(",")) == 20
        assert sum(len(dispatcher.incidents) for dispatcher in dispatchers) == 1
    finally:
        await cleanup_host(replica_stores[0], src_host)


async def test_1000_events_keep_the_incident_hash_small(
    replica_stores: Any, real_settings: Any, event_factory: Any
) -> None:
    """Opt-in: a capped incident's real memory footprint stays flat as events grow."""
    store = replica_stores[0]
    src_host = f"192.0.2.{uuid.uuid4().int % 250 + 1}"
    repository = IncidentRepository(store, real_settings, AuditLogger("test", stream=io.StringIO()))
    try:
        created: Incident | None = None
        footprint_at_cap = 0
        for port in range(1000):
            event = CanaryEvent.model_validate(event_factory(src_host=src_host, src_port=port + 1))
            result = await repository.record("ftp.login_attempt", event)
            if result is not None:
                created = result
            if port + 1 == real_settings.max_stored_events:
                assert created is not None
                footprint_at_cap = await store.client.memory_usage(created.key)
        assert created is not None

        fields = await store.hgetall(created.key)
        assert fields["events_count"] == "1000"
        assert fields["events_truncated"] == "True"
        assert len(fields["events_list"].split(",")) == real_settings.max_stored_events
        # Once the cap is reached the hash must stop growing: 900 more events
        # may only add the counter's digits, not another copy of the event list.
        footprint_final = await store.client.memory_usage(created.key)
        assert footprint_final <= footprint_at_cap * 1.1, (footprint_at_cap, footprint_final)
    finally:
        await cleanup_host(store, src_host)


async def test_vt_singleflight_across_real_redis_connections(
    replica_stores: Any, monkeypatch: Any
) -> None:
    """Two independent clients share one HTTP request and quota reservation."""
    token = uuid.uuid4().hex
    ip = str(ipaddress.ip_address(f"2606:4700::{token[:4]}:{token[4:8]}"))
    quota_key = f"test:vt-quota:{token}"
    entered = asyncio.Event()
    release = asyncio.Event()
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        entered.set()
        await release.wait()
        return httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": {}}}})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        clients = [
            VirusTotalClient(api_key="test-key", store=s, client=http) for s in replica_stores
        ]
        for client in clients:
            monkeypatch.setattr(client, "_quota_windows", lambda: [(quota_key, 100, 60000, "test")])
        tasks = [asyncio.create_task(clients[0].report(ip))]
        try:
            await asyncio.wait_for(entered.wait(), 2)
            tasks.extend(asyncio.create_task(clients[i % 2].report(ip)) for i in range(6))
            await asyncio.sleep(0.05)
            assert len(requests) == 1
            release.set()
            results = await asyncio.wait_for(asyncio.gather(*tasks), 3)
            assert all(result == results[0] for result in results)
            assert results[0][1] == "ok"
            assert len(requests) == 1
            assert await replica_stores[0].get_value(quota_key) == "1"
        finally:
            release.set()
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await replica_stores[0].delete(
                keys.enrichment_cache_key("vt", ip), keys.enrichment_lock_key("vt", ip), quota_key
            )


async def test_provider_pause_is_atomic_on_real_redis(replica_stores: Any) -> None:
    """Concurrent replicas cannot shorten an existing pause; TTL permits recovery."""
    key = f"test:vt-pause:{uuid.uuid4().hex}"
    first, second = replica_stores
    try:
        await asyncio.gather(
            first.extend_cached_value(key, "long", ttl=1),
            second.extend_cached_value(key, "short", ttl=0.1),
        )
        assert await first.get_value(key) == "long"
        assert await first.client.pttl(key) > 500
        await first.client.pexpire(key, 20)
        await asyncio.sleep(0.05)
        assert await second.get_value(key) is None
        assert await second.extend_cached_value(key, "recovered", ttl=1)
    finally:
        await first.delete(key)


@pytest.mark.linux
@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signal semantics required")
async def test_sigterm_stops_the_cli_cleanly(
    replica_stores: Any, free_tcp_port: Any, tmp_path: Any
) -> None:
    assert replica_stores
    env = {
        **os.environ,
        "OCC_REDIS_URL": REDIS_URL,
        "OCC_TCP_HOST": "127.0.0.1",
        "OCC_TCP_PORT": str(free_tcp_port),
        "OCC_SYSLOG_ENABLED": "false",
        "OCC_RATE_LIMIT_EVENTS_PER_MINUTE": "0",
    }
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "opencanary_correlator",
        "--health-port",
        "0",
        env=env,
        cwd=tmp_path,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + 15
        while True:
            try:
                _reader, writer = await asyncio.open_connection("127.0.0.1", free_tcp_port)
            except OSError:
                if loop.time() >= deadline:
                    raise
                await asyncio.sleep(0.05)
                continue
            writer.close()
            await writer.wait_closed()
            break

        process.send_signal(signal.SIGTERM)
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=20)
    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()

    assert process.returncode == 0, stderr.decode("utf-8", "replace")
    records = [
        json.loads(line)
        for line in stdout.decode("utf-8", "replace").splitlines()
        if line.startswith("{")
    ]
    actions = [record["action"] for record in records]
    assert "startup" in actions
    assert actions[-1] == "shutdown"
