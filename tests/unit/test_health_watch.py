"""Silent canaries: the per-node memory, the heartbeat field and the check.

A node that stops delivering is the one failure with no event attached to it, so
these tests are about the two places the evidence lives: the in-process registry
written on the ingest path, and the heartbeat field it publishes. The check is
then a plain window comparison - what the tests pin down is that it stays quiet
when it has no evidence, that it reports once rather than every interval, and
that a whole-estate outage does not become one message per canary.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from opencanary_correlator import metrics
from opencanary_correlator.connectors.base import BaseDispatcher, DispatchResult, IncidentLike
from opencanary_correlator.connectors.receivers._pipeline import EventPipeline
from opencanary_correlator.core.service_messages import ServiceKind, ServiceMessage, ServiceNotifier
from opencanary_correlator.core.stats import StatsReporter, _sum_heartbeat
from opencanary_correlator.core.watch import SILENT_PER_CHECK, HealthWatch, _minutes, last_seen
from opencanary_correlator.presence import NODE_FIELD_PREFIX, NodeRegistry
from opencanary_correlator.schemas import CanaryEvent
from opencanary_correlator.storage import keys

NOW = 1_793_262_400.0  # 2026-10-29 08:26:40 UTC


class RecordingDispatcher(BaseDispatcher):
    """A channel that keeps the service messages it is asked to send."""

    name = "recording"

    def __init__(self) -> None:
        self.messages: list[ServiceMessage] = []

    async def dispatch(self, incident: IncidentLike) -> DispatchResult:
        return DispatchResult(dispatcher=self.name, status="success")

    async def notify(self, message: ServiceMessage) -> DispatchResult:
        self.messages.append(message)
        return DispatchResult(dispatcher=self.name, status="success")


class NullSink:
    """Sink that accepts an event without correlating it."""

    async def handle_event(self, event: CanaryEvent) -> None:
        return None


def watch_settings(settings_factory: Any, **overrides: Any) -> Any:
    """Settings with the silence check on, which is not the default."""
    params: dict[str, Any] = {
        "service_enabled": True,
        "service_categories": ["canary"],
        "service_min_severity": "warning",
        "service_cooldown": 3600,
        "canary_silent_after": 600,
        "watch_interval": 60,
    }
    params.update(overrides)
    return settings_factory(**params)


def make_watch(store: Any, settings: Any, audit: Any, dispatcher: Any) -> HealthWatch:
    notifier = ServiceNotifier(store, [dispatcher], settings, audit)
    return HealthWatch(store, notifier, settings, audit, clock=lambda: NOW)


def ingestion_settings(settings_factory: Any, **overrides: Any) -> Any:
    """Settings with the ingestion thresholds armed and the silence check off."""
    params: dict[str, Any] = {
        "service_enabled": True,
        "service_categories": ["ingestion"],
        "service_min_severity": "warning",
        "service_cooldown": 3600,
        "canary_silent_after": 0,
        "watch_interval": 300,
        "service_drops_threshold": 3,
        "service_rejections_threshold": 3,
    }
    params.update(overrides)
    return settings_factory(**params)


def drop(reason: str, count: int = 1) -> None:
    """Count drops the way the ingest paths do."""
    metrics.EVENTS_DROPPED.labels(reason=reason).inc(count)


async def publish(store: Any, instance: str, nodes: dict[str, int]) -> None:
    """Write one replica heartbeat carrying node evidence and a counter."""
    fields: dict[str, Any] = {"events_accepted": 5}
    fields.update({f"{NODE_FIELD_PREFIX}{node}": stamp for node, stamp in nodes.items()})
    await store.write_heartbeat(keys.stats_instance_key(instance), fields, ttl=300)


def actions(audit_stream: Any) -> list[str]:
    return [json.loads(line)["action"] for line in audit_stream.getvalue().splitlines()]


# --- The registry -----------------------------------------------------------


def test_the_registry_keeps_the_newest_time_per_node() -> None:
    registry = NodeRegistry(clock=lambda: NOW)

    registry.touch("canary-1")
    registry.touch("canary-1", now=NOW + 60)

    assert registry.snapshot() == {"canary-1": int(NOW + 60)}


def test_a_full_registry_refuses_a_new_node_instead_of_evicting_one() -> None:
    """A spoofed `node_id` flood must not push a real canary out of the map.

    Evicting the oldest entry would let a peer inventing node ids hide the very
    node whose silence the map exists to report, so the limit refuses the new
    name and keeps the known ones.
    """
    registry = NodeRegistry(limit=2, clock=lambda: NOW)

    assert registry.touch("canary-1")
    assert registry.touch("canary-2")
    assert not registry.touch("canary-3")
    assert len(registry) == 2
    assert set(registry.snapshot()) == {"canary-1", "canary-2"}

    # A known node is still refreshed while the registry is full.
    assert registry.touch("canary-1", now=NOW + 30)
    assert registry.snapshot()["canary-1"] == int(NOW + 30)


def test_an_empty_node_id_is_ignored() -> None:
    registry = NodeRegistry(clock=lambda: NOW)

    assert not registry.touch("")
    assert len(registry) == 0


def test_the_published_snapshot_is_capped_to_the_newest_nodes() -> None:
    registry = NodeRegistry(clock=lambda: NOW)
    for index in range(5):
        registry.touch(f"canary-{index}", now=NOW + index)

    assert list(registry.snapshot(limit=2)) == ["canary-4", "canary-3"]
    assert registry.snapshot(limit=0) == {}


def test_the_ingest_path_records_the_node(audit: Any, event_factory: Any) -> None:
    """One dict write where the event is queued: no Redis, no lock."""
    registry = NodeRegistry(clock=lambda: NOW)
    pipeline = EventPipeline(sink=NullSink(), audit=audit, queue_size=10, nodes=registry)

    assert pipeline.submit(CanaryEvent.model_validate(event_factory(node_id="canary-7")))
    assert registry.snapshot() == {"canary-7": int(NOW)}


# --- Reading the heartbeats -------------------------------------------------


def test_the_newest_evidence_wins_across_replicas() -> None:
    """A node is silent only when *no* live replica saw it recently."""
    heartbeats = {
        "r1": {f"{NODE_FIELD_PREFIX}canary-1": str(int(NOW) - 1200), "events_accepted": "3"},
        "r2": {f"{NODE_FIELD_PREFIX}canary-1": str(int(NOW) - 30), "events_accepted": "1"},
        "r3": {"events_accepted": "9", "version": "0.5.0"},
    }

    assert last_seen(heartbeats) == {"canary-1": int(NOW) - 30}


def test_a_malformed_node_field_is_ignored() -> None:
    heartbeats = {"r1": {f"{NODE_FIELD_PREFIX}canary-1": "not-a-time"}}

    assert last_seen(heartbeats) == {}


# --- The check --------------------------------------------------------------


async def test_a_node_that_stopped_delivering_is_reported(
    store: Any, settings_factory: Any, audit: Any, audit_stream: Any
) -> None:
    dispatcher = RecordingDispatcher()
    watch = make_watch(store, watch_settings(settings_factory), audit, dispatcher)
    await publish(store, "r1", {"canary-1": int(NOW) - 1200})

    reported = await watch.check_once()

    assert reported == ("canary-1",)
    message = dispatcher.messages[0]
    assert message.kind is ServiceKind.CANARY_SILENT
    assert "canary-1" in message.title
    assert message.subject == "node:canary-1"
    assert "canary_silent" in actions(audit_stream)


async def test_a_node_inside_the_threshold_is_not_reported(
    store: Any, settings_factory: Any, audit: Any
) -> None:
    dispatcher = RecordingDispatcher()
    watch = make_watch(store, watch_settings(settings_factory), audit, dispatcher)
    await publish(store, "r1", {"canary-1": int(NOW) - 60})

    assert await watch.check_once() == ()
    assert dispatcher.messages == []


async def test_no_evidence_means_no_report(
    store: Any, settings_factory: Any, audit: Any, audit_stream: Any
) -> None:
    """A fresh deployment restarted a minute ago must not report every canary.

    The registry is memory: after a restart there is nothing to compare, and a
    missing heartbeat field is not evidence of silence.
    """
    dispatcher = RecordingDispatcher()
    watch = make_watch(store, watch_settings(settings_factory), audit, dispatcher)

    assert await watch.check_once() == ()
    assert dispatcher.messages == []
    assert "canary_silent" not in actions(audit_stream)


async def test_the_same_silent_node_is_reported_once_per_cooldown(
    store: Any, settings_factory: Any, audit: Any, audit_stream: Any
) -> None:
    dispatcher = RecordingDispatcher()
    watch = make_watch(store, watch_settings(settings_factory), audit, dispatcher)
    await publish(store, "r1", {"canary-1": int(NOW) - 1200})

    await watch.check_once()
    await watch.check_once()

    assert len(dispatcher.messages) == 1
    assert "service_message_suppressed" in actions(audit_stream)


async def test_a_disabled_check_reads_nothing(
    store: Any, settings_factory: Any, audit: Any
) -> None:
    dispatcher = RecordingDispatcher()
    settings = watch_settings(settings_factory, canary_silent_after=0)
    watch = make_watch(store, settings, audit, dispatcher)
    await publish(store, "r1", {"canary-1": int(NOW) - 1200})

    assert await watch.check_once() == ()
    assert dispatcher.messages == []


async def test_a_replica_that_lost_the_election_does_nothing(
    store: Any, settings_factory: Any, audit: Any
) -> None:
    """Every replica runs the loop; one check per interval is enough."""
    dispatcher = RecordingDispatcher()
    watch = make_watch(store, watch_settings(settings_factory), audit, dispatcher)
    await publish(store, "r1", {"canary-1": int(NOW) - 1200})

    async with store.lock(keys.watch_lock_key()) as acquired:
        assert acquired
        assert await watch.check_once() == ()

    assert dispatcher.messages == []
    # Once the lock is free the same evidence is still there.
    assert await watch.check_once() == ("canary-1",)


async def test_a_mass_outage_is_summarised_instead_of_flooding(
    store: Any, settings_factory: Any, audit: Any
) -> None:
    dispatcher = RecordingDispatcher()
    watch = make_watch(store, watch_settings(settings_factory), audit, dispatcher)
    nodes = {f"canary-{index:02d}": int(NOW) - 1200 for index in range(SILENT_PER_CHECK + 2)}
    await publish(store, "r1", nodes)

    reported = await watch.check_once()

    assert len(reported) == SILENT_PER_CHECK + 2
    individual = [message for message in dispatcher.messages if message.subject.startswith("node:")]
    summary = [message for message in dispatcher.messages if message.subject == "canary:bulk"]
    assert len(individual) == SILENT_PER_CHECK
    assert len(summary) == 1
    assert summary[0].count == 2


# --- The heartbeat field ----------------------------------------------------


async def test_the_heartbeat_carries_node_evidence(store: Any, audit: Any) -> None:
    """The registry travels in the hash the digest already publishes."""
    registry = NodeRegistry(clock=lambda: NOW)
    registry.touch("canary-1")
    reporter = StatsReporter(store, audit, nodes=registry, clock=lambda: NOW)

    await reporter.beat()

    fields = (await store.live_heartbeats())[reporter.instance_id]
    assert fields[f"{NODE_FIELD_PREFIX}canary-1"] == str(int(NOW))


# --- Ingestion thresholds ---------------------------------------------------


async def test_a_burst_of_drops_is_reported_with_its_reasons(
    store: Any, settings_factory: Any, audit: Any
) -> None:
    """The counter already exists; nobody watching a phone sees it."""
    dispatcher = RecordingDispatcher()
    watch = make_watch(store, ingestion_settings(settings_factory), audit, dispatcher)

    drop("queue_full", 4)
    drop("incident_lock_timeout", 1)
    await watch.check_once()

    assert len(dispatcher.messages) == 1
    message = dispatcher.messages[0]
    assert message.kind is ServiceKind.INGESTION_DROPPED
    assert message.subject == "ingestion:dropped"
    assert "5" in message.title
    by_reason = next(line for line in message.lines if line.startswith("By reason:"))
    assert "queue_full 4" in by_reason
    assert "incident_lock_timeout 1" in by_reason


async def test_drops_below_the_threshold_stay_in_the_audit_trail(
    store: Any, settings_factory: Any, audit: Any
) -> None:
    """One malformed payload is not news for a phone."""
    dispatcher = RecordingDispatcher()
    watch = make_watch(store, ingestion_settings(settings_factory), audit, dispatcher)

    drop("queue_full", 2)
    await watch.check_once()

    assert dispatcher.messages == []


async def test_only_drops_since_the_previous_check_are_counted(
    store: Any, settings_factory: Any, audit: Any
) -> None:
    """The counters are cumulative; the report is a window, not a total."""
    first = RecordingDispatcher()
    drop("queue_full", 2)
    make_watch(store, ingestion_settings(settings_factory), audit, first)

    # A new watch is the next interval: the two drops above are its baseline.
    second = RecordingDispatcher()
    watch = make_watch(store, ingestion_settings(settings_factory), audit, second)

    assert await watch.check_once() == ()
    assert second.messages == []

    drop("queue_full", 4)
    await watch.check_once()

    assert len(second.messages) == 1
    assert "4" in second.messages[0].title


async def test_a_burst_of_rejected_payloads_is_reported(
    store: Any, settings_factory: Any, audit: Any
) -> None:
    dispatcher = RecordingDispatcher()
    watch = make_watch(store, ingestion_settings(settings_factory), audit, dispatcher)

    metrics.EVENTS_TOTAL.labels(result="rejected").inc(5)
    await watch.check_once()

    assert len(dispatcher.messages) == 1
    assert dispatcher.messages[0].kind is ServiceKind.INGESTION_REJECTED
    assert dispatcher.messages[0].subject == "ingestion:rejected"


async def test_a_zero_threshold_disables_that_report(
    store: Any, settings_factory: Any, audit: Any
) -> None:
    dispatcher = RecordingDispatcher()
    settings = ingestion_settings(
        settings_factory, service_drops_threshold=0, service_rejections_threshold=0
    )
    watch = make_watch(store, settings, audit, dispatcher)

    drop("queue_full", 50)
    metrics.EVENTS_TOTAL.labels(result="rejected").inc(50)
    await watch.check_once()

    assert dispatcher.messages == []


async def test_more_than_four_reasons_are_summarised(
    store: Any, settings_factory: Any, audit: Any
) -> None:
    """A line per reason would make the message unreadable in Telegram."""
    dispatcher = RecordingDispatcher()
    watch = make_watch(store, ingestion_settings(settings_factory), audit, dispatcher)

    for reason in ("queue_full", "dispatch_failed", "incident_lock_timeout", "shutdown", "other"):
        drop(reason, 2)
    await watch.check_once()

    by_reason = next(line for line in dispatcher.messages[0].lines if line.startswith("By reason:"))
    assert "+1 more" in by_reason


# --- The scheduler -----------------------------------------------------------


def test_a_silence_duration_is_rendered_in_readable_units() -> None:
    assert _minutes(300) == "5 min"
    assert _minutes(3 * 3600 + 120) == "3 h 2 min"
    assert _minutes(3 * 24 * 3600) == "3 days"


def fast_watch(store: Any, settings_factory: Any, audit: Any, dispatcher: Any) -> HealthWatch:
    """A watch whose interval is short enough for a test to observe."""
    settings = ingestion_settings(settings_factory).model_copy(update={"watch_interval": 0.01})
    return make_watch(store, settings, audit, dispatcher)


async def test_the_loop_checks_once_per_interval_and_stops(
    store: Any, settings_factory: Any, audit: Any
) -> None:
    watch = fast_watch(store, settings_factory, audit, RecordingDispatcher())
    calls: list[int] = []

    async def counting() -> None:
        calls.append(1)

    watch.check_once = counting  # type: ignore[method-assign]

    await watch.start()
    await asyncio.sleep(0.05)
    await watch.stop()

    assert len(calls) >= 2
    assert watch._task is None


async def test_a_failing_check_is_audited_and_the_loop_continues(
    store: Any, settings_factory: Any, audit: Any, audit_stream: Any
) -> None:
    """A broken window must not stop the next one from running."""
    watch = fast_watch(store, settings_factory, audit, RecordingDispatcher())
    calls: list[int] = []

    async def boom() -> None:
        calls.append(1)
        raise RuntimeError("redis down")

    watch.check_once = boom  # type: ignore[method-assign]

    await watch.start()
    await asyncio.sleep(0.05)
    await watch.stop()

    assert len(calls) >= 2
    assert "health_watch_failed" in actions(audit_stream)


def test_the_digest_ignores_node_evidence() -> None:
    """Node times are not counters: summing them would poison the totals."""
    totals: dict[str, int] = {}

    _sum_heartbeat(
        "r1",
        {"events_accepted": "5", f"{NODE_FIELD_PREFIX}canary-1": "1234567890"},
        totals,
    )

    assert totals == {"events_accepted": 5}
