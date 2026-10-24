"""Tests for the Redis-backed window primitives."""

from __future__ import annotations

from opencanary_correlator.core.windows import (
    DedupCache,
    DistinctSetWindow,
    SlidingWindow,
    event_fingerprint,
)
from opencanary_correlator.schemas import CanaryEvent


async def test_dedup_accepts_a_fingerprint_once(store) -> None:
    cache = DedupCache(store, ttl=60)

    assert await cache.first_seen("fingerprint") is True
    assert await cache.first_seen("fingerprint") is False
    assert await cache.first_seen("other") is True


async def test_dedup_is_disabled_by_zero_ttl(store) -> None:
    cache = DedupCache(store, ttl=0)

    assert await cache.first_seen("fingerprint") is True
    assert await cache.first_seen("fingerprint") is True


async def test_distinct_window_counts_unique_members(store) -> None:
    window = DistinctSetWindow(store, "test:distinct", ttl=50)

    assert await window.add("21") == 1
    assert await window.add("21") == 1
    assert await window.add("22") == 2
    assert await window.members() == {"21", "22"}

    await window.clear()
    assert await window.members() == set()
    assert await window.add("23") == 1


async def test_sliding_window_trims_entries_outside_the_horizon(store) -> None:
    window = SlidingWindow(store, "test:sliding", horizon=50)

    assert await window.add("a", timestamp=1000) == 1
    assert await window.add("b", timestamp=1040) == 2
    assert await window.add("c", timestamp=1060) == 2
    assert await window.add("d", timestamp=1120) == 1


def test_fingerprint_is_stable_and_distinguishes_events(event_factory) -> None:
    event = CanaryEvent.model_validate(event_factory())
    same = CanaryEvent.model_validate(event_factory())
    other_port = CanaryEvent.model_validate(event_factory(src_port=5555))
    other_logdata = CanaryEvent.model_validate(event_factory(logdata={"USERNAME": "root"}))

    assert event_fingerprint(event) == event_fingerprint(same)
    assert event_fingerprint(event) != event_fingerprint(other_port)
    assert event_fingerprint(event) != event_fingerprint(other_logdata)
    assert len(event_fingerprint(event)) == 64
