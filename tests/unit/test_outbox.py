"""The alert outbox: a decided notification either arrives or is visible."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from opencanary_correlator.connectors.base import BaseDispatcher, DispatchResult, IncidentLike
from opencanary_correlator.constants import KEY_INCIDENTS
from opencanary_correlator.core.engine import CorrelationEngine
from opencanary_correlator.core.incident import Incident, IncidentRepository
from opencanary_correlator.core.outbox import BACKOFF_SECONDS, AlertOutbox
from opencanary_correlator.core.rules import build_rules
from opencanary_correlator.core.windows import DedupCache
from opencanary_correlator.schemas import CanaryEvent
from opencanary_correlator.storage.keys import delivered_key, outbox_alert_key


class RecordingDispatcher(BaseDispatcher):
    name = "recording"

    def __init__(self) -> None:
        self.incidents: list[Incident] = []

    async def dispatch(self, incident: IncidentLike) -> DispatchResult:
        assert isinstance(incident, Incident)
        self.incidents.append(incident)
        return DispatchResult(dispatcher=self.name, status="success")


class FailingDispatcher(BaseDispatcher):
    name = "recording"

    def __init__(self) -> None:
        self.calls = 0

    async def dispatch(self, incident: IncidentLike) -> DispatchResult:
        self.calls += 1
        return DispatchResult(dispatcher=self.name, status="error", detail="503")


class RaisingDispatcher(BaseDispatcher):
    name = "recording"

    async def dispatch(self, incident: IncidentLike) -> DispatchResult:
        raise RuntimeError("channel down")


def make_repository(store: Any, settings: Any, audit: Any, clock: Any, channels: tuple[str, ...]):
    return IncidentRepository(store, settings, audit, clock=clock, alert_channels=channels)


def make_engine(
    store: Any,
    settings: Any,
    audit: Any,
    clock: Any,
    dispatcher: BaseDispatcher,
    *,
    outbox: AlertOutbox | None,
) -> CorrelationEngine:
    repository = make_repository(store, settings, audit, clock, outbox.channels if outbox else ())
    return CorrelationEngine(
        rules=build_rules(store, repository, settings),
        dispatchers=[dispatcher],
        dedup=DedupCache(store, ttl=settings.dedup_ttl, lease=settings.dedup_lease),
        settings=settings,
        audit=audit,
        clock=clock,
        outbox=outbox,
    )


async def test_a_new_incident_enqueues_one_delivery_per_channel(
    store: Any, settings_factory: Any, audit: Any, clock: Any, event_factory: Any
) -> None:
    repository = make_repository(store, settings_factory(), audit, clock, ("telegram", "smtp"))
    event = CanaryEvent.model_validate(event_factory())

    incident = await repository.record("ftp.login_attempt", event)

    assert incident is not None
    assert await store.outbox_pending() == 2
    entry = await store.read_alert(f"{incident.key}#telegram")
    assert entry is not None
    assert entry["channel"] == "telegram"
    assert entry["incident"] == incident.key
    assert entry["attempts"] == "0"


async def test_a_merge_enqueues_nothing(
    store: Any, settings_factory: Any, audit: Any, clock: Any, event_factory: Any
) -> None:
    repository = make_repository(store, settings_factory(), audit, clock, ("telegram",))
    first = CanaryEvent.model_validate(event_factory(src_port=40000))
    second = CanaryEvent.model_validate(event_factory(src_port=40001))

    assert await repository.record("ftp.login_attempt", first) is not None
    assert await repository.record("ftp.login_attempt", second) is None

    # The merge notified nobody, so it owed nobody: one incident, one delivery.
    assert await store.outbox_pending() == 1


async def test_a_successful_inline_delivery_settles_the_entry(
    store: Any, settings_factory: Any, audit: Any, clock: Any, event_factory: Any
) -> None:
    settings = settings_factory()
    dispatcher = RecordingDispatcher()
    outbox = AlertOutbox(store, [dispatcher], settings, audit, clock=clock)
    engine = make_engine(store, settings, audit, clock, dispatcher, outbox=outbox)

    await engine.handle_event(CanaryEvent.model_validate(event_factory()))

    assert len(dispatcher.incidents) == 1
    assert await store.outbox_pending() == 0
    assert await store.exists(delivered_key(f"{dispatcher.incidents[0].key}#recording"))


async def test_a_failed_inline_delivery_is_rescheduled_with_a_backoff(
    store: Any, settings_factory: Any, audit: Any, clock: Any, event_factory: Any
) -> None:
    settings = settings_factory()
    dispatcher = FailingDispatcher()
    outbox = AlertOutbox(store, [dispatcher], settings, audit, clock=clock)
    engine = make_engine(store, settings, audit, clock, dispatcher, outbox=outbox)

    await engine.handle_event(CanaryEvent.model_validate(event_factory()))
    incident_key = (await store.zrangebyscore(KEY_INCIDENTS, "-inf", "+inf"))[0]
    entry = await store.read_alert(f"{incident_key}#recording")

    assert entry is not None
    assert entry["attempts"] == "1"
    assert entry["last_error"] == "error"
    # Scheduled, not due: the first retry waits out the first backoff.
    assert await store.claim_due_alerts(now=clock(), limit=10, lease=60.0) == []
    clock.advance(BACKOFF_SECONDS[0] + 0.1)
    assert await store.claim_due_alerts(now=clock(), limit=10, lease=60.0) == [
        f"{incident_key}#recording"
    ]


async def test_the_worker_delivers_what_the_process_dropped(
    store: Any, settings_factory: Any, audit: Any, clock: Any, event_factory: Any
) -> None:
    """A crash between the incident write and the dispatch loses nothing."""
    settings = settings_factory()
    dispatcher = RaisingDispatcher()
    outbox = AlertOutbox(store, [dispatcher], settings, audit, clock=clock)
    engine = make_engine(store, settings, audit, clock, dispatcher, outbox=outbox)
    await engine.handle_event(CanaryEvent.model_validate(event_factory()))
    assert await store.outbox_pending() == 1

    recovered = RecordingDispatcher()
    worker = AlertOutbox(store, [recovered], settings, audit, clock=clock)
    clock.advance(BACKOFF_SECONDS[0] + 0.1)

    assert await worker.run_once() == 1
    assert len(recovered.incidents) == 1
    assert await store.outbox_pending() == 0


async def test_a_delivery_is_buried_after_its_last_attempt(
    store: Any, settings_factory: Any, audit: Any, audit_stream: Any, clock: Any, event_factory: Any
) -> None:
    settings = settings_factory(outbox_max_attempts=1)
    dispatcher = FailingDispatcher()
    outbox = AlertOutbox(store, [dispatcher], settings, audit, clock=clock)
    engine = make_engine(store, settings, audit, clock, dispatcher, outbox=outbox)
    await engine.handle_event(CanaryEvent.model_validate(event_factory()))

    clock.advance(BACKOFF_SECONDS[0] + 0.1)
    assert await outbox.run_once() == 0

    assert await store.outbox_pending() == 0
    assert await store.outbox_dead() == 1
    assert "alert_dead_letter" in audit_stream.getvalue()


async def test_an_unknown_channel_is_buried_instead_of_retried(
    store: Any, settings_factory: Any, audit: Any, audit_stream: Any, clock: Any, event_factory: Any
) -> None:
    settings = settings_factory()
    repository = make_repository(store, settings, audit, clock, ("telegram",))
    event = CanaryEvent.model_validate(event_factory())
    incident = await repository.record("ftp.login_attempt", event)
    assert incident is not None

    # The worker has no Telegram dispatcher: it cannot ever deliver this.
    worker = AlertOutbox(store, [RecordingDispatcher()], settings, audit, clock=clock)

    assert await worker.run_once() == 0
    assert await store.outbox_dead() == 1
    assert "unknown_channel" in audit_stream.getvalue()


async def test_a_delivery_whose_incident_is_gone_is_buried(
    store: Any, settings_factory: Any, audit: Any, audit_stream: Any, clock: Any
) -> None:
    """The entry names an incident an operator (or a TTL) removed."""
    settings = settings_factory()
    entry_id = "incident:ftplogin:10.0.0.9:1#recording"
    await store.enqueue_alert(
        entry_id, incident_key="incident:ftplogin:10.0.0.9:1", channel="recording", score=clock()
    )
    worker = AlertOutbox(store, [RecordingDispatcher()], settings, audit, clock=clock)

    assert await worker.run_once() == 0
    assert await store.outbox_dead() == 1
    assert "incident_gone" in audit_stream.getvalue()


async def test_a_timing_out_channel_is_retried_not_buried(
    store: Any, settings_factory: Any, audit: Any, audit_stream: Any, clock: Any, event_factory: Any
) -> None:
    settings = settings_factory(dispatch_timeout=0.01)

    class SlowDispatcher(BaseDispatcher):
        name = "recording"

        async def dispatch(self, incident: IncidentLike) -> DispatchResult:
            await asyncio.sleep(0.2)
            return DispatchResult(dispatcher=self.name, status="success")

    repository = make_repository(store, settings, audit, clock, ("recording",))
    await repository.record("ftp.login_attempt", CanaryEvent.model_validate(event_factory()))
    worker = AlertOutbox(store, [SlowDispatcher()], settings, audit, clock=clock)

    assert await worker.run_once() == 0

    assert await store.outbox_pending() == 1
    assert await store.outbox_dead() == 0
    assert '"reason":"timeout"' in audit_stream.getvalue()


async def test_two_replicas_never_claim_the_same_delivery(
    store: Any, settings_factory: Any, audit: Any, clock: Any, event_factory: Any
) -> None:
    settings = settings_factory()
    repository = make_repository(store, settings, audit, clock, ("telegram",))
    await repository.record("ftp.login_attempt", CanaryEvent.model_validate(event_factory()))

    first = await store.claim_due_alerts(now=clock(), limit=10, lease=60.0)
    second = await store.claim_due_alerts(now=clock(), limit=10, lease=60.0)

    assert len(first) == 1
    assert second == []
    # The lease expires and the entry is due again for whoever is still alive.
    assert await store.claim_due_alerts(now=clock() + 61, limit=10, lease=60.0) == first


async def test_settling_an_entry_that_never_existed_is_harmless(
    store: Any, settings_factory: Any, audit: Any, clock: Any
) -> None:
    settings = settings_factory()
    outbox = AlertOutbox(store, [RecordingDispatcher()], settings, audit, clock=clock)

    await outbox.settle("incident:ftplogin:10.0.0.5:1#recording", "recording", error=None)

    assert not await store.exists(outbox_alert_key("incident:ftplogin:10.0.0.5:1#recording"))


async def test_a_broken_worker_iteration_is_audited_and_the_loop_survives(
    store: Any, settings_factory: Any, audit: Any, audit_stream: Any, clock: Any
) -> None:
    settings = settings_factory()
    outbox = AlertOutbox(store, [RecordingDispatcher()], settings, audit, clock=clock)

    async def explode() -> int:
        raise RuntimeError("redis hiccup")

    await outbox.start()
    outbox.run_once = explode  # type: ignore[method-assign]

    await asyncio.sleep(0.05)
    await outbox.stop()

    assert "outbox_failed" in audit_stream.getvalue()


def test_the_backoff_grows_and_then_holds() -> None:
    assert BACKOFF_SECONDS == tuple(sorted(BACKOFF_SECONDS))
    assert BACKOFF_SECONDS[0] == pytest.approx(1.0)
