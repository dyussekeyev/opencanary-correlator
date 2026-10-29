"""The daily digest: heartbeat sums, the once-a-day election and the rendering."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from opencanary_correlator.connectors.base import BaseDispatcher, DispatchResult, IncidentLike
from opencanary_correlator.core.digest import DigestScheduler, next_run, render_digest
from opencanary_correlator.core.service_messages import ServiceKind, ServiceMessage, ServiceNotifier
from opencanary_correlator.core.stats import StatsReporter, collect_digest
from opencanary_correlator.storage import keys

NOW = 1_793_262_400.0  # 2026-10-29 08:26:40 UTC


class RecordingDispatcher(BaseDispatcher):
    """A channel that keeps the messages it is asked to send."""

    name = "slack"

    def __init__(self, name: str = "slack") -> None:
        self.name = name  # type: ignore[misc]
        self.messages: list[ServiceMessage] = []

    async def dispatch(self, incident: IncidentLike) -> DispatchResult:
        return DispatchResult(dispatcher=self.name, status="success")

    async def notify(self, message: ServiceMessage) -> DispatchResult:
        self.messages.append(message)
        return DispatchResult(dispatcher=self.name, status="success")


def digest_settings(settings_factory: Any, **overrides: Any) -> Any:
    params: dict[str, Any] = {
        "digest_enabled": True,
        "digest_time": "03:00",
        "digest_top_sources": 5,
        "digest_channels": [],
    }
    params.update(overrides)
    return settings_factory(**params)


def make_notifier(store: Any, settings: Any, audit: Any, dispatchers: list[BaseDispatcher]) -> Any:
    return ServiceNotifier(store, dispatchers, settings, audit)


# --- Scheduling arithmetic --------------------------------------------------


def test_the_next_run_is_today_or_tomorrow() -> None:
    before = datetime(2026, 10, 29, 2, 0, tzinfo=UTC).timestamp()
    after = datetime(2026, 10, 29, 4, 0, tzinfo=UTC).timestamp()

    assert next_run(before, "03:00") == pytest.approx(
        datetime(2026, 10, 29, 3, 0, tzinfo=UTC).timestamp()
    )
    assert next_run(after, "03:00") == pytest.approx(
        datetime(2026, 10, 30, 3, 0, tzinfo=UTC).timestamp()
    )


def test_exactly_on_the_hour_waits_for_the_next_day() -> None:
    moment = datetime(2026, 10, 29, 3, 0, tzinfo=UTC).timestamp()

    # "Strictly after": a run that already happened must not schedule itself again.
    assert next_run(moment, "03:00") == pytest.approx(
        datetime(2026, 10, 30, 3, 0, tzinfo=UTC).timestamp()
    )


# --- Heartbeats -------------------------------------------------------------


async def test_a_beat_publishes_the_counters_with_a_ttl(store: Any, audit: Any) -> None:
    reporter = StatsReporter(store, audit, instance_id="replica-a", clock=lambda: NOW)

    await reporter.beat()

    fields = await store.hgetall(keys.stats_instance_key("replica-a"))
    assert fields["started"] == str(int(NOW))
    assert "events_accepted" in fields and "alerts_success" in fields
    assert "version" in fields
    ttl = await store.client.ttl(keys.stats_instance_key("replica-a"))
    assert 0 < ttl <= 300


async def test_two_replicas_are_summed_and_an_expired_one_is_excluded(
    store: Any, audit: Any
) -> None:
    first = StatsReporter(store, audit, instance_id="replica-a", clock=lambda: NOW)
    second = StatsReporter(store, audit, instance_id="replica-b", clock=lambda: NOW)
    await store.write_heartbeat(first.key, {"events_accepted": 10, "alerts_success": 2}, ttl=300)
    await store.write_heartbeat(second.key, {"events_accepted": 5, "alerts_success": 3}, ttl=300)

    data = await collect_digest(store, now=NOW, top_sources=0)

    assert data.replicas == 2
    assert data.events["accepted"] == 15
    assert data.alerts["success"] == 5

    # A replica that stopped heartbeating lets its key expire; here it is deleted.
    await store.delete(second.key)
    data = await collect_digest(store, now=NOW, top_sources=0)

    assert data.replicas == 1
    assert data.events["accepted"] == 10


async def test_a_replica_that_cannot_heartbeat_does_not_crash(
    store: Any, audit: Any, audit_stream: Any, monkeypatch: Any
) -> None:
    reporter = StatsReporter(store, audit, instance_id="replica-a", clock=lambda: NOW)

    async def explode(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("redis hiccup")

    monkeypatch.setattr(store, "write_heartbeat", explode)

    await reporter.start()
    await reporter.stop()

    assert "stats_heartbeat_failed" in audit_stream.getvalue()


# --- The digest window ------------------------------------------------------


async def test_incidents_outside_the_window_are_not_counted(store: Any, audit: Any) -> None:
    fresh = "incident:rdplogin:74.22.3.1:1793200000"
    stale = "incident:rdplogin:74.22.3.2:1700000000"
    await store.client.zadd("incidents", {fresh: NOW - 3600, stale: NOW - 3 * 86400})

    data = await collect_digest(store, now=NOW, top_sources=5)

    assert data.incidents == 1
    assert data.top_sources == (("74.22.3.1", 1),)


async def test_the_busiest_sources_are_ranked_and_parsed_across_key_shapes(
    store: Any, audit: Any
) -> None:
    """An IPv6 source has colons of its own; the timestamp is the only one after it."""
    entries = {
        "incident:rdplogin:74.22.3.1:1793200000": NOW - 60,
        "incident:ftplogin:74.22.3.1:1793200001": NOW - 120,
        "incident:ftplogin:2001:db8::1:1793200002": NOW - 180,
    }
    await store.client.zadd("incidents", entries)

    data = await collect_digest(store, now=NOW, top_sources=5)

    assert data.top_sources[0] == ("74.22.3.1", 2)
    assert ("2001:db8::1", 1) in data.top_sources


async def test_zero_top_sources_skips_the_section(store: Any, audit: Any) -> None:
    await store.client.zadd("incidents", {"incident:rdplogin:74.22.3.1:1793200000": NOW - 60})

    data = await collect_digest(store, now=NOW, top_sources=0)

    assert data.top_sources == ()
    assert data.incidents == 1


async def test_the_quota_counters_are_read(store: Any, audit: Any) -> None:
    stamp = datetime.fromtimestamp(NOW, tz=UTC)
    await store.set_value(keys.quota_key("virustotal", "day", stamp.strftime("%Y%m%d")), "42")
    await store.set_value(keys.quota_key("virustotal", "month", stamp.strftime("%Y%m")), "777")

    data = await collect_digest(store, now=NOW, top_sources=0)

    assert (data.quota_day, data.quota_month) == (42, 777)


# --- The scheduler ----------------------------------------------------------


def make_scheduler(
    store: Any, settings: Any, audit: Any, dispatcher: RecordingDispatcher
) -> DigestScheduler:
    notifier = make_notifier(store, settings, audit, [dispatcher])
    return DigestScheduler(store, notifier, settings, audit, clock=lambda: NOW)


async def test_one_digest_per_day(
    store: Any, settings_factory: Any, audit: Any, audit_stream: Any
) -> None:
    dispatcher = RecordingDispatcher()
    settings = digest_settings(settings_factory, digest_channels=["slack"])
    scheduler = make_scheduler(store, settings, audit, dispatcher)

    assert await scheduler.run_once() is True
    assert await scheduler.run_once() is False

    assert len(dispatcher.messages) == 1
    assert dispatcher.messages[0].kind is ServiceKind.DIGEST_DAILY
    assert '"action":"digest_sent"' in audit_stream.getvalue()
    # The day is marked, so even a replica that lost the lock next time is a no-op.
    day = datetime.fromtimestamp(NOW, tz=UTC).strftime("%Y-%m-%d")
    assert await store.exists(keys.digest_sent_key(day))


async def test_a_replica_that_lost_the_lock_sends_nothing(
    store: Any, settings_factory: Any, audit: Any
) -> None:
    dispatcher = RecordingDispatcher()
    settings = digest_settings(settings_factory, digest_channels=["slack"])
    scheduler = make_scheduler(store, settings, audit, dispatcher)
    day = datetime.fromtimestamp(NOW, tz=UTC).strftime("%Y-%m-%d")

    async with store.lock(keys.digest_lock_key(day)) as acquired:
        assert acquired
        assert await scheduler.run_once() is False

    assert dispatcher.messages == []


async def test_the_digest_works_with_service_messages_switched_off(
    store: Any, settings_factory: Any, audit: Any
) -> None:
    """The digest has its own switch; the notifier's `enabled` gate is for reports."""
    dispatcher = RecordingDispatcher()
    settings = digest_settings(settings_factory, service_enabled=False, digest_channels=["slack"])
    scheduler = make_scheduler(store, settings, audit, dispatcher)

    assert await scheduler.run_once() is True
    assert len(dispatcher.messages) == 1


async def test_the_digest_routing_is_separate_from_alerts(
    store: Any, settings_factory: Any, audit: Any
) -> None:
    telegram = RecordingDispatcher(name="telegram")
    smtp = RecordingDispatcher(name="smtp")
    settings = digest_settings(settings_factory, digest_channels=["smtp"])
    notifier = make_notifier(store, settings, audit, [telegram, smtp])
    scheduler = DigestScheduler(store, notifier, settings, audit, clock=lambda: NOW)

    assert await scheduler.run_once() is True

    assert telegram.messages == []
    assert len(smtp.messages) == 1


async def test_an_empty_digest_routing_falls_back_to_the_service_routing(
    store: Any, settings_factory: Any, audit: Any
) -> None:
    telegram = RecordingDispatcher(name="telegram")
    smtp = RecordingDispatcher(name="smtp")
    settings = digest_settings(settings_factory, service_channels=["telegram"])
    notifier = make_notifier(store, settings, audit, [telegram, smtp])
    scheduler = DigestScheduler(store, notifier, settings, audit, clock=lambda: NOW)

    assert await scheduler.run_once() is True

    assert len(telegram.messages) == 1
    assert smtp.messages == []


# --- Rendering --------------------------------------------------------------


def test_the_digest_reports_the_window_and_the_sources(store: Any, audit: Any) -> None:
    import asyncio

    async def build() -> Any:
        await store.client.zadd("incidents", {"incident:rdplogin:74.22.3.1:1793200000": NOW - 60})
        await store.write_heartbeat(
            keys.stats_instance_key("a"),
            {"events_accepted": 120, "alerts_success": 7},
            ttl=300,
        )
        return await collect_digest(store, now=NOW, top_sources=5)

    data = asyncio.run(build())
    title, lines = render_digest(data)
    text = "\r\n".join((title, *lines))

    assert title.startswith("daily digest 2026-10-29")
    assert "Incidents: 1" in text
    assert "Events: 120 accepted" in text
    assert "Alerts: 7 delivered" in text
    assert "74.22.3.1: 1" in text
    assert "Replicas: 1" in text


# --- Configuration ----------------------------------------------------------


def test_a_malformed_digest_time_is_rejected(settings_factory: Any) -> None:
    with pytest.raises(ValidationError, match="digest_time"):
        settings_factory(digest_time="3am")


@pytest.mark.parametrize(("value", "expected"), [("3:05", "03:05"), ("23:59", "23:59")])
def test_a_valid_digest_time_is_normalised(
    settings_factory: Any, value: str, expected: str
) -> None:
    assert settings_factory(digest_time=value).digest_time == expected


def test_the_digest_is_off_and_lists_five_sources_by_default(settings_factory: Any) -> None:
    settings = settings_factory()

    assert settings.digest_enabled is False
    assert settings.digest_time == "03:00"
    assert settings.digest_top_sources == 5
    assert settings.digest_channels == []


def test_an_unknown_digest_channel_is_rejected(settings_factory: Any) -> None:
    with pytest.raises(ValidationError, match="service_channels"):
        settings_factory(digest_channels=["telegrm"])


def test_the_top_sources_section_can_be_disabled_but_not_negative(
    settings_factory: Any,
) -> None:
    assert settings_factory(digest_top_sources=0).digest_top_sources == 0
    with pytest.raises(ValidationError):
        settings_factory(digest_top_sources=-1)
