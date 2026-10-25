"""Correlation engine: routing, deduplication and dispatcher fault tolerance."""

from __future__ import annotations

import asyncio
import json
from typing import Any

from opencanary_correlator.connectors.base import BaseDispatcher, DispatchResult, IncidentLike
from opencanary_correlator.constants import KEY_INCIDENTS
from opencanary_correlator.core.engine import CorrelationEngine
from opencanary_correlator.core.incident import Incident, IncidentRepository
from opencanary_correlator.core.rules import Rule, build_rules
from opencanary_correlator.core.windows import DedupCache
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
    store: Any, settings: Any, audit: Any, clock: Any, dispatchers: Any, rules: Any = None
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
    )


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


async def test_duplicate_event_is_deduplicated(
    store: Any, settings_factory: Any, audit: Any, clock: Any, event_factory: Any
) -> None:
    dispatcher = RecordingDispatcher()
    engine = make_engine(store, settings_factory(), audit, clock, [dispatcher])
    event = login_event(event_factory)

    await engine.handle_event(event)
    await engine.handle_event(event)

    assert len(dispatcher.incidents) == 1


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


async def test_incident_is_persisted_without_dispatchers(
    store: Any, settings_factory: Any, audit: Any, clock: Any, event_factory: Any
) -> None:
    engine = make_engine(store, settings_factory(), audit, clock, [])

    await engine.handle_event(login_event(event_factory))

    keys = await store.zrangebyscore(KEY_INCIDENTS, "-inf", "+inf")
    assert len(keys) == 1
    fields = await store.hgetall(keys[0])
    assert fields["acknowledged"] == "False"
