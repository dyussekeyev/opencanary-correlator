"""Correlation engine: routing, deduplication and dispatcher fault tolerance."""

from __future__ import annotations

import asyncio
import contextlib
import json
from collections.abc import AsyncIterator
from typing import Any

from opencanary_correlator.connectors.base import BaseDispatcher, DispatchResult, IncidentLike
from opencanary_correlator.constants import KEY_INCIDENTS
from opencanary_correlator.core.engine import CorrelationEngine
from opencanary_correlator.core.incident import Incident, IncidentRepository
from opencanary_correlator.core.rules import Rule, build_rules
from opencanary_correlator.core.windows import DedupCache
from opencanary_correlator.enrichment.models import Enrichment, GeoInfo
from opencanary_correlator.schemas import CanaryEvent


class RecordingDispatcher(BaseDispatcher):
    """Dispatcher that records incidents it received."""

    name = "recording"

    def __init__(self) -> None:
        self.incidents: list[Incident] = []

    async def dispatch(self, incident: IncidentLike) -> DispatchResult:
        assert isinstance(incident, Incident)
        self.incidents.append(incident)
        return DispatchResult(dispatcher=self.name, status="success")


class FailingDispatcher(BaseDispatcher):
    """Dispatcher that always raises."""

    name = "failing"

    async def dispatch(self, incident: IncidentLike) -> DispatchResult:
        raise RuntimeError("channel down")


class SlowDispatcher(BaseDispatcher):
    """Dispatcher that never finishes in time."""

    name = "slow"

    async def dispatch(self, incident: IncidentLike) -> DispatchResult:
        await asyncio.sleep(1)
        return DispatchResult(dispatcher=self.name, status="success")


class BrokenRule(Rule):
    """Rule that always raises."""

    name = "broken"

    def matches(self, event: CanaryEvent) -> bool:
        return True

    async def apply(self, event: CanaryEvent, *, now: float) -> list[Incident]:
        raise RuntimeError("rule bug")


def make_engine(
    store: Any,
    settings: Any,
    audit: Any,
    clock: Any,
    dispatchers: Any,
    rules: Any = None,
    enricher: Any = None,
) -> CorrelationEngine:
    repository = IncidentRepository(store, settings, audit, clock=clock)
    engine_rules = rules if rules is not None else build_rules(store, repository, settings)
    return CorrelationEngine(
        rules=engine_rules,
        dispatchers=dispatchers,
        dedup=DedupCache(store, ttl=settings.dedup_ttl),
        settings=settings,
        audit=audit,
        clock=clock,
        enricher=enricher,
    )


class RecordingEnricher:
    """Enricher stand-in that records calls and can fail on demand."""

    def __init__(self, result: Any = None, error: Exception | None = None) -> None:
        self.result = result or Enrichment(geo=GeoInfo(country_code="NL", country="Netherlands"))
        self.error = error
        self.calls: list[str] = []

    async def enrich(self, src_host: str) -> Any:
        self.calls.append(src_host)
        if self.error is not None:
            raise self.error
        return self.result


def audit_actions(audit_stream: Any) -> list[str]:
    return [json.loads(line)["action"] for line in audit_stream.getvalue().splitlines()]


def login_event(event_factory: Any) -> CanaryEvent:
    return CanaryEvent.model_validate(event_factory())


async def test_login_event_creates_incident_and_notifies(
    store: Any, settings_factory: Any, audit: Any, audit_stream: Any, clock: Any, event_factory: Any
) -> None:
    dispatcher = RecordingDispatcher()
    engine = make_engine(store, settings_factory(), audit, clock, [dispatcher])

    await engine.handle_event(login_event(event_factory))

    assert len(dispatcher.incidents) == 1
    assert dispatcher.incidents[0].INCIDENT_NAME == "ftp.login_attempt"
    assert len(await store.zrangebyscore(KEY_INCIDENTS, "-inf", "+inf")) == 1
    assert "alert_dispatch" in audit_actions(audit_stream)


async def test_two_logtypes_from_one_host_in_one_second_both_leave_a_trace(
    store: Any,
    settings_factory: Any,
    audit: Any,
    audit_stream: Any,
    clock: Any,
    event_factory: Any,
) -> None:
    """A field report of a silently lost MySQL event next to an RDP one.

    Same source host and same second must not collapse into one another: the
    dedup fingerprint carries the log type, destination port and log data, and
    the incident key carries the incident type, so both events have to produce
    their own incident and their own audit record.
    """
    dispatcher = RecordingDispatcher()
    engine = make_engine(store, settings_factory(), audit, clock, [dispatcher])
    rdp = CanaryEvent.model_validate(
        event_factory(logtype=14001, dst_port=3389, logdata={"USERNAME": "Administrator"})
    )
    mysql = CanaryEvent.model_validate(
        event_factory(logtype=8001, dst_port=3306, logdata={"USERNAME": "root"})
    )

    await engine.handle_event(rdp)
    await engine.handle_event(mysql)

    assert sorted(incident.INCIDENT_NAME for incident in dispatcher.incidents) == [
        "mysql.login_attempt",
        "rdp.login_attempt",
    ]
    actions = audit_actions(audit_stream)
    assert actions.count("incident_created") == 2
    assert "event_deduplicated" not in actions
    assert "event_unrouted" not in actions


async def test_a_merged_event_is_audited_even_though_it_does_not_notify(
    store: Any, settings_factory: Any, audit: Any, audit_stream: Any, clock: Any, event_factory: Any
) -> None:
    """`record()` returns None for a merge, which must not mean "no trace".

    A merge suppresses the notification on purpose; without its own audit record
    the event looks lost to whoever greps the trail after a missing alert.
    """
    dispatcher = RecordingDispatcher()
    engine = make_engine(store, settings_factory(), audit, clock, [dispatcher])

    await engine.handle_event(CanaryEvent.model_validate(event_factory(src_port=40000)))
    await engine.handle_event(CanaryEvent.model_validate(event_factory(src_port=40001)))

    assert len(dispatcher.incidents) == 1
    actions = audit_actions(audit_stream)
    assert actions.count("incident_created") == 1
    assert actions.count("incident_updated") == 1


async def test_enrichment_is_attached_before_dispatch(
    store: Any, settings_factory: Any, audit: Any, clock: Any, event_factory: Any
) -> None:
    dispatcher = RecordingDispatcher()
    enricher = RecordingEnricher()
    engine = make_engine(store, settings_factory(), audit, clock, [dispatcher], enricher=enricher)

    await engine.handle_event(login_event(event_factory))

    assert enricher.calls == ["10.0.0.5"]
    assert dispatcher.incidents[0].enrichment is enricher.result


async def test_a_broken_enricher_still_delivers_the_alert(
    store: Any, settings_factory: Any, audit: Any, audit_stream: Any, clock: Any, event_factory: Any
) -> None:
    dispatcher = RecordingDispatcher()
    enricher = RecordingEnricher(error=RuntimeError("lookup exploded"))
    engine = make_engine(store, settings_factory(), audit, clock, [dispatcher], enricher=enricher)

    await engine.handle_event(login_event(event_factory))

    assert len(dispatcher.incidents) == 1
    assert dispatcher.incidents[0].enrichment is None
    assert "enrichment_failed" in audit_actions(audit_stream)


async def test_a_merged_event_is_not_enriched(
    store: Any, settings_factory: Any, audit: Any, clock: Any, event_factory: Any
) -> None:
    """One alert per incident means one lookup per alert, not per event."""
    dispatcher = RecordingDispatcher()
    enricher = RecordingEnricher()
    engine = make_engine(store, settings_factory(), audit, clock, [dispatcher], enricher=enricher)

    await engine.handle_event(login_event(event_factory))
    clock.advance(1)
    await engine.handle_event(
        CanaryEvent.model_validate(event_factory(logdata={"USERNAME": "root"}))
    )

    assert enricher.calls == ["10.0.0.5"]
    assert len(dispatcher.incidents) == 1


async def test_duplicate_event_is_deduplicated(
    store: Any, settings_factory: Any, audit: Any, clock: Any, event_factory: Any
) -> None:
    dispatcher = RecordingDispatcher()
    engine = make_engine(store, settings_factory(), audit, clock, [dispatcher])
    event = login_event(event_factory)

    await engine.handle_event(event)
    await engine.handle_event(event)

    assert len(dispatcher.incidents) == 1


async def test_node_lifecycle_logtypes_are_ignored_quietly(
    store: Any, settings_factory: Any, audit: Any, audit_stream: Any, clock: Any, event_factory: Any
) -> None:
    """Boot, base-message and ping records are expected noise, not routing bugs."""
    dispatcher = RecordingDispatcher()
    engine = make_engine(store, settings_factory(), audit, clock, [dispatcher])

    for logtype in (1000, 1001, 1002, 1003, 1004):
        await engine.handle_event(CanaryEvent.model_validate(event_factory(logtype=logtype)))

    records = [json.loads(line) for line in audit_stream.getvalue().splitlines()]
    actions = [record["action"] for record in records]
    assert "event_unrouted" not in actions
    assert actions.count("event_ignored") == 5
    assert {record["status"] for record in records if record["action"] == "event_ignored"} == {
        "info"
    }
    assert dispatcher.incidents == []


async def test_unknown_logtype_is_audited(
    store: Any, settings_factory: Any, audit: Any, audit_stream: Any, clock: Any, event_factory: Any
) -> None:
    dispatcher = RecordingDispatcher()
    engine = make_engine(store, settings_factory(), audit, clock, [dispatcher])
    event = CanaryEvent.model_validate(event_factory(logtype=77777))

    await engine.handle_event(event)

    assert dispatcher.incidents == []
    assert "event_unrouted" in audit_actions(audit_stream)


async def test_failing_dispatcher_does_not_block_others(
    store: Any, settings_factory: Any, audit: Any, audit_stream: Any, clock: Any, event_factory: Any
) -> None:
    recording = RecordingDispatcher()
    engine = make_engine(
        store,
        settings_factory(),
        audit,
        clock,
        [FailingDispatcher(), recording],
    )

    await engine.handle_event(login_event(event_factory))

    assert len(recording.incidents) == 1
    errors = [
        json.loads(line)
        for line in audit_stream.getvalue().splitlines()
        if json.loads(line)["action"] == "alert_dispatch" and json.loads(line)["status"] == "error"
    ]
    assert errors and errors[0]["details"]["error_type"] == "RuntimeError"


async def test_slow_dispatcher_times_out(
    store: Any, settings_factory: Any, audit: Any, audit_stream: Any, clock: Any, event_factory: Any
) -> None:
    engine = make_engine(
        store,
        settings_factory(dispatch_timeout=0.05),
        audit,
        clock,
        [SlowDispatcher()],
    )

    await engine.handle_event(login_event(event_factory))

    timeouts = [
        json.loads(line)
        for line in audit_stream.getvalue().splitlines()
        if json.loads(line)["action"] == "alert_dispatch"
    ]
    assert timeouts and timeouts[0]["details"]["reason"] == "timeout"


async def test_broken_rule_does_not_prevent_other_rules(
    store: Any, settings_factory: Any, audit: Any, audit_stream: Any, clock: Any, event_factory: Any
) -> None:
    dispatcher = RecordingDispatcher()
    repository = IncidentRepository(store, settings_factory(), audit, clock=clock)
    rules: list[Rule] = [BrokenRule(), *build_rules(store, repository, settings_factory())]
    engine = make_engine(store, settings_factory(), audit, clock, [dispatcher], rules=rules)

    await engine.handle_event(login_event(event_factory))

    assert len(dispatcher.incidents) == 1
    assert "rule_failed" in audit_actions(audit_stream)


async def test_a_failed_rule_releases_the_dedup_claim(
    store: Any, settings_factory: Any, audit: Any, audit_stream: Any, clock: Any, event_factory: Any
) -> None:
    """A claim taken before the rules must not outlive a failure they hit.

    Nothing was stored, so the redelivery of the same event (a second syslog
    relay, a canary that reconnects) has to be correlated again instead of being
    answered `event_deduplicated` for `OCC_DEDUP_TTL`.
    """
    engine = make_engine(
        store,
        settings_factory(),
        audit,
        clock,
        [RecordingDispatcher()],
        rules=[BrokenRule()],
    )
    event = login_event(event_factory)

    await engine.handle_event(event)
    await engine.handle_event(event)

    actions = audit_actions(audit_stream)
    assert actions.count("rule_failed") == 2
    assert "event_deduplicated" not in actions


async def test_a_lock_timeout_does_not_confirm_the_dedup_claim(
    store: Any,
    settings_factory: Any,
    audit: Any,
    audit_stream: Any,
    clock: Any,
    event_factory: Any,
    monkeypatch: Any,
) -> None:
    """An event that was never stored must not be remembered as seen.

    `record()` raises when the per-host lock times out, and the engine withdraws
    the claim. Otherwise the same event redelivered - a second syslog relay, a
    canary that reconnects - would be answered `event_deduplicated` for
    `OCC_DEDUP_TTL` while no incident existed, which is the silent loss a field
    report described: an event with no incident, no rejection and no dedup
    record of its own.
    """
    dispatcher = RecordingDispatcher()
    engine = make_engine(store, settings_factory(), audit, clock, [dispatcher])
    event = login_event(event_factory)

    real_lock = store.lock
    state = {"timeout": True}

    @contextlib.asynccontextmanager
    async def flaky_lock(key: str, **kwargs: Any) -> AsyncIterator[bool]:
        if state["timeout"]:
            yield False
            return
        async with real_lock(key, **kwargs) as acquired:
            yield acquired

    monkeypatch.setattr(store, "lock", flaky_lock)

    await engine.handle_event(event)

    assert dispatcher.incidents == []
    assert await store.zrangebyscore(KEY_INCIDENTS, "-inf", "+inf") == []
    actions = audit_actions(audit_stream)
    assert "incident_lock_timeout" in actions
    assert "event_dropped" in actions
    # A storage timeout is not a rule failure: blaming the rule would hide the
    # real cause from whoever reads the audit trail after a missing alert.
    assert "rule_failed" not in actions
    assert "event_unrouted" not in actions

    state["timeout"] = False
    await engine.handle_event(event)

    assert len(dispatcher.incidents) == 1
    assert "event_deduplicated" not in audit_actions(audit_stream)


async def test_incident_is_persisted_without_dispatchers(
    store: Any, settings_factory: Any, audit: Any, clock: Any, event_factory: Any
) -> None:
    engine = make_engine(store, settings_factory(), audit, clock, [])

    await engine.handle_event(login_event(event_factory))

    keys = await store.zrangebyscore(KEY_INCIDENTS, "-inf", "+inf")
    assert len(keys) == 1
    fields = await store.hgetall(keys[0])
    assert fields["acknowledged"] == "False"
