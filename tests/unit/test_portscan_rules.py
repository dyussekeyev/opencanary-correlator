"""Port-scan rules: thresholds, dedup of repeated ports and target tracking."""

from __future__ import annotations

import json
from typing import Any

from opencanary_correlator.connectors.receivers._pipeline import ReceiverStats
from opencanary_correlator.core.incident import IncidentRepository
from opencanary_correlator.core.rules.portscan import (
    HostPortScanRule,
    NetworkPortScanRule,
)
from opencanary_correlator.schemas import CanaryEvent
from opencanary_correlator.storage import keys
from opencanary_correlator.storage.redis_store import RedisStore


def syn_event(event_factory: Any, *, dst_port: int, **overrides: Any) -> CanaryEvent:
    return CanaryEvent.model_validate(
        event_factory(logtype=5001, dst_port=dst_port, logdata={}, **overrides)
    )


def make_repository(store: RedisStore, settings: Any, audit: Any, clock: Any) -> IncidentRepository:
    return IncidentRepository(store, settings, audit, clock=clock)


async def test_host_portscan_fires_at_threshold_and_clears_window(
    store: Any, settings_factory: Any, audit: Any, clock: Any, event_factory: Any
) -> None:
    settings = settings_factory(scan_host_threshold=3, scan_host_horizon=50)
    repository = make_repository(store, settings, audit, clock)
    rule = HostPortScanRule(store=store, repository=repository, settings=settings)

    assert await rule.apply(syn_event(event_factory, dst_port=21), now=clock.now) == []
    assert await rule.apply(syn_event(event_factory, dst_port=22), now=clock.now) == []

    incidents = await rule.apply(syn_event(event_factory, dst_port=23), now=clock.now)

    assert len(incidents) == 1
    incident = incidents[0]
    assert incident.INCIDENT_NAME == "scans.host_portscan"
    assert incident.logtype == 5003
    assert json.loads(incident.logdata or "[]") == [21, 22, 23]
    assert await store.exists(keys.host_scan_key("10.0.0.5", "10.0.0.2")) is False


async def test_host_portscan_dedups_repeated_port(
    store: Any, settings_factory: Any, audit: Any, clock: Any, event_factory: Any
) -> None:
    settings = settings_factory(scan_host_threshold=3)
    repository = make_repository(store, settings, audit, clock)
    rule = HostPortScanRule(store=store, repository=repository, settings=settings)

    for _ in range(6):
        incidents = await rule.apply(syn_event(event_factory, dst_port=21), now=clock.now)
        assert incidents == []

    assert await store.exists(keys.host_scan_key("10.0.0.5", "10.0.0.2")) is True


async def test_host_portscan_window_ttl_does_not_slide(
    store: Any, fake_redis: Any, settings_factory: Any, audit: Any, clock: Any, event_factory: Any
) -> None:
    settings = settings_factory(scan_host_threshold=5, scan_host_horizon=50)
    repository = make_repository(store, settings, audit, clock)
    rule = HostPortScanRule(store=store, repository=repository, settings=settings)
    key = keys.host_scan_key("10.0.0.5", "10.0.0.2")

    assert await rule.apply(syn_event(event_factory, dst_port=21), now=clock.now) == []
    assert 0 < await fake_redis.ttl(key) <= 50

    await fake_redis.expire(key, 5)
    assert await rule.apply(syn_event(event_factory, dst_port=22), now=clock.now) == []

    assert 0 < await fake_redis.ttl(key) <= 5


async def test_network_portscan_window_ttl_does_not_slide(
    store: Any, fake_redis: Any, settings_factory: Any, audit: Any, clock: Any, event_factory: Any
) -> None:
    settings = settings_factory(scan_network_threshold=5, scan_network_horizon=50)
    repository = make_repository(store, settings, audit, clock)
    rule = NetworkPortScanRule(store=store, repository=repository, settings=settings)
    key = keys.network_scan_key("10.0.0.5", 22)

    first = syn_event(event_factory, dst_port=22, reported_dst_host="127.0.0.1")
    second = syn_event(event_factory, dst_port=22, reported_dst_host="127.0.0.2")
    assert await rule.apply(first, now=clock.now) == []
    assert 0 < await fake_redis.ttl(key) <= 50

    await fake_redis.expire(key, 5)
    assert await rule.apply(second, now=clock.now) == []

    assert 0 < await fake_redis.ttl(key) <= 5


async def test_network_portscan_uses_reported_target(
    store: Any, settings_factory: Any, audit: Any, clock: Any, event_factory: Any
) -> None:
    settings = settings_factory(scan_network_threshold=2, scan_network_horizon=3600)
    repository = make_repository(store, settings, audit, clock)
    rule = NetworkPortScanRule(store=store, repository=repository, settings=settings)

    first = syn_event(
        event_factory,
        dst_port=22,
        dst_host="192.168.1.10",
        reported_dst_host="127.0.0.1",
    )
    second = syn_event(
        event_factory,
        dst_port=22,
        dst_host="192.168.1.11",
        reported_dst_host="127.0.0.2",
    )

    assert await rule.apply(first, now=clock.now) == []
    incidents = await rule.apply(second, now=clock.now)

    assert len(incidents) == 1
    incident = incidents[0]
    assert incident.INCIDENT_NAME == "scans.network_portscan"
    assert incident.logtype == 5002
    assert json.loads(incident.logdata or "[]") == ["127.0.0.1", "127.0.0.2"]


async def test_network_portscan_ignores_repeated_target(
    store: Any, settings_factory: Any, audit: Any, clock: Any, event_factory: Any
) -> None:
    settings = settings_factory(scan_network_threshold=2)
    repository = make_repository(store, settings, audit, clock)
    rule = NetworkPortScanRule(store=store, repository=repository, settings=settings)
    event = syn_event(event_factory, dst_port=22)

    assert await rule.apply(event, now=clock.now) == []
    assert await rule.apply(event, now=clock.now) == []


async def test_failed_record_keeps_the_threshold_evidence_for_retry(
    store: Any, settings_factory: Any, audit: Any, clock: Any, event_factory: Any, monkeypatch: Any
) -> None:
    import pytest

    settings = settings_factory(scan_host_threshold=3)
    repository = make_repository(store, settings, audit, clock)
    rule = HostPortScanRule(store=store, repository=repository, settings=settings)
    for port in (21, 22):
        await rule.apply(syn_event(event_factory, dst_port=port), now=clock())
    original = store.save_new_incident

    async def fail(*args: Any, **kwargs: Any) -> None:
        raise ConnectionError("storage unavailable")

    monkeypatch.setattr(store, "save_new_incident", fail)
    with pytest.raises(ConnectionError):
        await rule.apply(syn_event(event_factory, dst_port=23), now=clock())
    monkeypatch.setattr(store, "save_new_incident", original)
    incidents = await rule.apply(syn_event(event_factory, dst_port=24), now=clock())
    assert len(incidents) == 1
    assert {21, 22, 23} <= set(json.loads(incidents[0].logdata))


async def test_snapshot_survives_restart_and_new_generation_is_not_cleared(
    store: Any, settings_factory: Any, audit: Any, clock: Any, event_factory: Any
) -> None:
    settings = settings_factory(scan_host_threshold=2)
    repository = make_repository(store, settings, audit, clock)
    key = keys.host_scan_key("10.0.0.5", "10.0.0.2")
    event = syn_event(event_factory, dst_port=22)
    await store.snapshot_scan(
        key, member="21", ttl=1, threshold=2, event=event.model_dump_json(), now=clock()
    )
    pending = await store.snapshot_scan(
        key, member="22", ttl=1, threshold=2, event=event.model_dump_json(), now=clock()
    )
    await store.sadd_with_fixed_expire(key, "23", ttl=50)
    restarted = HostPortScanRule(store=store, repository=repository, settings=settings)
    incidents = await restarted.recover()
    assert len(incidents) == 1
    assert json.loads(incidents[0].logdata) == [21, 22]
    assert await store.smembers(key) == {"23"}
    assert not await store.exists(pending)
    assert await restarted.recover() == []


def test_receiver_stats_defaults() -> None:
    stats = ReceiverStats()

    assert (stats.accepted, stats.rejected, stats.dropped) == (0, 0, 0)
