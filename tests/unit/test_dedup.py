"""Dedup claims: a lease while the work runs, a window once it is done."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from opencanary_correlator.connectors.base import BaseDispatcher, DispatchResult, IncidentLike
from opencanary_correlator.core.engine import CorrelationEngine
from opencanary_correlator.core.incident import Incident, IncidentRepository
from opencanary_correlator.core.rules import build_rules
from opencanary_correlator.core.windows import DEFAULT_DEDUP_LEASE, DedupCache, event_fingerprint
from opencanary_correlator.schemas import CanaryEvent
from opencanary_correlator.storage.keys import dedup_key


def make_cache(store: Any, ttl: float = 60.0, lease: float = 10.0) -> DedupCache:
    return DedupCache(store, ttl=ttl, lease=lease)


async def pttl(store: Any, fingerprint: str) -> int:
    return int(await store.client.pttl(dedup_key(fingerprint)))


async def test_the_lease_is_shorter_than_the_window(store: Any) -> None:
    cache = make_cache(store, ttl=60.0, lease=0.2)

    token = await cache.claim("fingerprint")

    assert token is not None
    assert 0 < await pttl(store, "fingerprint") <= 200


async def test_confirm_extends_the_claim_to_the_full_window(store: Any) -> None:
    cache = make_cache(store, ttl=60.0, lease=0.2)

    token = await cache.claim("fingerprint")
    assert token is not None
    assert await cache.confirm("fingerprint", token)

    assert await pttl(store, "fingerprint") > 50_000


async def test_an_abandoned_claim_does_not_swallow_the_redelivery(store: Any) -> None:
    """A process that dies mid-correlation must not suppress the retry.

    This is the ordering finding: the claim used to be written for the whole
    dedup window before anything was persisted, so a crash left a key that made
    the canary's redelivery look like a duplicate of work that never happened.
    """
    cache = make_cache(store, ttl=60.0, lease=0.05)
    assert await cache.claim("fingerprint") is not None
    assert await cache.claim("fingerprint") is None  # still in flight

    await asyncio.sleep(0.15)

    assert await cache.claim("fingerprint") is not None


async def test_a_holder_cannot_confirm_a_claim_it_lost(store: Any) -> None:
    cache = make_cache(store, ttl=60.0, lease=0.05)
    first = await cache.claim("fingerprint")
    assert first is not None
    await asyncio.sleep(0.15)
    second = await cache.claim("fingerprint")
    assert second is not None and second != first

    assert not await cache.confirm("fingerprint", first)
    # The new holder's lease is untouched by the stale confirm.
    assert await pttl(store, "fingerprint") <= 200


async def test_release_only_withdraws_its_own_claim(store: Any) -> None:
    cache = make_cache(store, ttl=60.0, lease=0.05)
    stale = await cache.claim("fingerprint")
    assert stale is not None
    await asyncio.sleep(0.15)
    fresh = await cache.claim("fingerprint")
    assert fresh is not None

    await cache.release("fingerprint", stale)
    assert await store.exists(dedup_key("fingerprint"))

    await cache.release("fingerprint", fresh)
    assert not await store.exists(dedup_key("fingerprint"))


async def test_zero_ttl_disables_deduplication(store: Any) -> None:
    cache = make_cache(store, ttl=0.0)

    assert await cache.claim("fingerprint") is not None
    assert await cache.claim("fingerprint") is not None
    assert await cache.confirm("fingerprint", "token")
    await cache.release("fingerprint", "token")
    assert not await store.exists(dedup_key("fingerprint"))


async def test_the_lease_is_clamped_to_the_window(store: Any) -> None:
    """A lease longer than the window would keep a claim alive past its TTL."""
    cache = make_cache(store, ttl=0.05, lease=3600.0)

    token = await cache.claim("fingerprint")
    assert token is not None

    assert await pttl(store, "fingerprint") <= 50


def test_the_default_lease_is_shorter_than_the_default_window() -> None:
    assert DEFAULT_DEDUP_LEASE < 60.0


class RecordingDispatcher(BaseDispatcher):
    name = "recording"

    def __init__(self) -> None:
        self.incidents: list[Incident] = []

    async def dispatch(self, incident: IncidentLike) -> DispatchResult:
        assert isinstance(incident, Incident)
        self.incidents.append(incident)
        return DispatchResult(dispatcher=self.name, status="success")


class BrokenRule:
    name = "broken"

    def matches(self, event: CanaryEvent) -> bool:
        return True

    async def apply(self, event: CanaryEvent, *, now: float) -> list[Incident]:
        raise RuntimeError("rule bug")


class SlowRule:
    """Rule that outlives a deliberately tiny lease."""

    name = "slow"

    def matches(self, event: CanaryEvent) -> bool:
        return True

    async def apply(self, event: CanaryEvent, *, now: float) -> list[Incident]:
        await asyncio.sleep(0.1)
        return []


async def test_a_rule_that_outlives_its_lease_is_recorded(
    store: Any,
    settings_factory: Any,
    audit: Any,
    audit_stream: Any,
    clock: Any,
    event_factory: Any,
) -> None:
    """The lease is a visible signal when work takes longer than it promises."""
    settings = settings_factory(dedup_lease=0.02)
    engine = CorrelationEngine(
        rules=[SlowRule()],
        dispatchers=[],
        dedup=DedupCache(store, ttl=settings.dedup_ttl, lease=settings.dedup_lease),
        settings=settings,
        audit=audit,
        clock=clock,
    )

    await engine.handle_event(CanaryEvent.model_validate(event_factory()))

    assert "event_dedup_lease_lost" in audit_stream.getvalue()


async def test_a_redelivery_after_an_abandoned_claim_still_correlates(
    store: Any, settings_factory: Any, audit: Any, clock: Any, event_factory: Any
) -> None:
    """End to end: an orphaned claim must not cost the incident."""
    settings = settings_factory(dedup_lease=0.05)
    dispatcher = RecordingDispatcher()
    repository = IncidentRepository(store, settings, audit, clock=clock)
    engine = CorrelationEngine(
        rules=build_rules(store, repository, settings),
        dispatchers=[dispatcher],
        dedup=DedupCache(store, ttl=settings.dedup_ttl, lease=settings.dedup_lease),
        settings=settings,
        audit=audit,
        clock=clock,
    )
    event = CanaryEvent.model_validate(event_factory())
    # Somebody claimed it and died before persisting: the fingerprint is live.
    assert await DedupCache(store, ttl=60.0, lease=0.05).claim(event_fingerprint(event))
    await asyncio.sleep(0.15)

    await engine.handle_event(event)

    assert len(dispatcher.incidents) == 1


async def test_a_correlated_event_keeps_its_claim_for_the_whole_window(
    store: Any, settings_factory: Any, audit: Any, clock: Any, event_factory: Any
) -> None:
    """The opposite direction: a real duplicate must still be suppressed."""
    settings = settings_factory(dedup_lease=10.0)
    dispatcher = RecordingDispatcher()
    repository = IncidentRepository(store, settings, audit, clock=clock)
    engine = CorrelationEngine(
        rules=build_rules(store, repository, settings),
        dispatchers=[dispatcher],
        dedup=DedupCache(store, ttl=settings.dedup_ttl, lease=settings.dedup_lease),
        settings=settings,
        audit=audit,
        clock=clock,
    )
    event = CanaryEvent.model_validate(event_factory())

    await engine.handle_event(event)
    await engine.handle_event(event)

    assert len(dispatcher.incidents) == 1
    assert await pttl(store, event_fingerprint(event)) > int(settings.dedup_ttl * 1000) - 5_000


@pytest.mark.parametrize("lease", [0.0, -1.0])
def test_the_configuration_rejects_a_lease_that_is_not_positive(
    settings_factory: Any, lease: float
) -> None:
    with pytest.raises(ValueError):
        settings_factory(dedup_lease=lease)
