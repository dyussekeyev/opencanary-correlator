"""Replica-safety: duplicates collapse to one incident and one notification."""

from __future__ import annotations

import asyncio
import io
from typing import Any

import pytest

from opencanary_correlator.audit import AuditLogger
from opencanary_correlator.connectors.base import BaseDispatcher, DispatchResult, IncidentLike
from opencanary_correlator.constants import KEY_INCIDENTS
from opencanary_correlator.core.engine import CorrelationEngine
from opencanary_correlator.core.incident import Incident, IncidentRepository
from opencanary_correlator.core.rules import build_rules
from opencanary_correlator.core.windows import DedupCache
from opencanary_correlator.schemas import CanaryEvent
from opencanary_correlator.storage.redis_store import RedisStore

pytestmark = pytest.mark.integration


class CountingDispatcher(BaseDispatcher):
    """Dispatcher counting deliveries."""

    name = "counting"

    def __init__(self) -> None:
        self.incidents: list[Incident] = []
        self._lock = asyncio.Lock()

    async def dispatch(self, incident: IncidentLike) -> DispatchResult:
        assert isinstance(incident, Incident)
        async with self._lock:
            self.incidents.append(incident)
        return DispatchResult(dispatcher=self.name, status="success")


def build_engine(
    store: RedisStore, settings: Any, audit: Any, dispatcher: CountingDispatcher
) -> Any:
    repository = IncidentRepository(store, settings, audit)
    return CorrelationEngine(
        rules=build_rules(store, repository, settings),
        dispatchers=[dispatcher],
        dedup=DedupCache(store, ttl=settings.dedup_ttl),
        settings=settings,
        audit=audit,
    )


async def test_duplicate_events_across_replicas_notify_once(
    fake_redis: Any, settings_factory: Any, event_factory: Any
) -> None:
    store = RedisStore(fake_redis)
    settings = settings_factory()
    audit = AuditLogger("replica", stream=io.StringIO())
    dispatchers = [CountingDispatcher() for _ in range(2)]
    engines = [build_engine(store, settings, audit, dispatcher) for dispatcher in dispatchers]
    event = CanaryEvent.model_validate(event_factory())

    await asyncio.gather(*(engine.handle_event(event) for engine in engines for _ in range(25)))

    keys = await store.zrangebyscore(KEY_INCIDENTS, "-inf", "+inf")
    assert len(keys) == 1
    deliveries = sum(len(dispatcher.incidents) for dispatcher in dispatchers)
    assert deliveries == 1


async def test_concurrent_distinct_events_merge_into_one_incident(
    fake_redis: Any, settings_factory: Any, event_factory: Any
) -> None:
    store = RedisStore(fake_redis)
    settings = settings_factory()
    audit = AuditLogger("replica", stream=io.StringIO())
    dispatchers = [CountingDispatcher() for _ in range(2)]
    engines = [build_engine(store, settings, audit, dispatcher) for dispatcher in dispatchers]
    events = [
        CanaryEvent.model_validate(event_factory(src_port=40000 + offset)) for offset in range(20)
    ]

    await asyncio.gather(
        *(engines[index % 2].handle_event(event) for index, event in enumerate(events))
    )

    keys = await store.zrangebyscore(KEY_INCIDENTS, "-inf", "+inf")
    assert len(keys) == 1
    fields = await store.hgetall(keys[0])
    assert fields["events_count"] == "20"
    assert len(fields["events_list"].split(",")) == 20
    deliveries = [len(dispatcher.incidents) for dispatcher in dispatchers]
    assert sum(deliveries) == 1


async def test_200_concurrent_events_on_one_host_merge_atomically(
    fake_redis: Any, settings_factory: Any, event_factory: Any
) -> None:
    """Past the cap, concurrent merges still produce one incident and one alert."""
    store = RedisStore(fake_redis)
    settings = settings_factory()
    audit = AuditLogger("replica", stream=io.StringIO())
    dispatchers = [CountingDispatcher() for _ in range(2)]
    engines = [build_engine(store, settings, audit, dispatcher) for dispatcher in dispatchers]
    events = [
        CanaryEvent.model_validate(event_factory(src_port=40000 + offset)) for offset in range(200)
    ]

    await asyncio.gather(
        *(engines[index % 2].handle_event(event) for index, event in enumerate(events))
    )

    keys = await store.zrangebyscore(KEY_INCIDENTS, "-inf", "+inf")
    assert len(keys) == 1
    fields = await store.hgetall(keys[0])
    assert fields["events_count"] == "200"
    assert fields["events_truncated"] == "True"
    assert len(fields["events_list"].split(",")) == settings.max_stored_events
    assert sum(len(dispatcher.incidents) for dispatcher in dispatchers) == 1
