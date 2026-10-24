"""Port-scan rules: thresholds, dedup of repeated ports and target tracking."""

from __future__ import annotations

import json

from opencanary_correlator.connectors.receivers._pipeline import ReceiverStats
from opencanary_correlator.core.incident import IncidentRepository
from opencanary_correlator.core.rules.portscan import (
    HostPortScanRule,
    NetworkPortScanRule,
)
from opencanary_correlator.schemas import CanaryEvent
from opencanary_correlator.storage import keys
from opencanary_correlator.storage.redis_store import RedisStore


def syn_event(event_factory, *, dst_port: int, **overrides) -> CanaryEvent:
    return CanaryEvent.model_validate(
        event_factory(logtype=5001, dst_port=dst_port, logdata={}, **overrides)
    )


def make_repository(store: RedisStore, settings, audit, clock) -> IncidentRepository:
    return IncidentRepository(store, settings, audit, clock=clock)


async def test_host_portscan_fires_at_threshold_and_clears_window(
    store, settings_factory, audit, clock, event_factory
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
    store, settings_factory, audit, clock, event_factory
) -> None:
    settings = settings_factory(scan_host_threshold=3)
    repository = make_repository(store, settings, audit, clock)
    rule = HostPortScanRule(store=store, repository=repository, settings=settings)

    for _ in range(6):
        incidents = await rule.apply(syn_event(event_factory, dst_port=21), now=clock.now)
        assert incidents == []

    assert await store.exists(keys.host_scan_key("10.0.0.5", "10.0.0.2")) is True


async def test_host_portscan_window_ttl_does_not_slide(
    store, fake_redis, settings_factory, audit, clock, event_factory
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
    store, fake_redis, settings_factory, audit, clock, event_factory
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
    store, settings_factory, audit, clock, event_factory
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
    store, settings_factory, audit, clock, event_factory
) -> None:
    settings = settings_factory(scan_network_threshold=2)
    repository = make_repository(store, settings, audit, clock)
    rule = NetworkPortScanRule(store=store, repository=repository, settings=settings)
    event = syn_event(event_factory, dst_port=22)

    assert await rule.apply(event, now=clock.now) == []
    assert await rule.apply(event, now=clock.now) == []


def test_receiver_stats_defaults() -> None:
    stats = ReceiverStats()

    assert (stats.accepted, stats.rejected, stats.dropped) == (0, 0, 0)
