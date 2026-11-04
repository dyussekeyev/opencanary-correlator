"""Retention and dead letters: delete only what nothing still owes.

Every case here is a deletion decision, so the tests state the safe direction
explicitly: disabled by default, an owed delivery protects its incident, and a
replay is one idempotent requeue rather than an edit of live state.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from opencanary_correlator.app.parser import build_parser
from opencanary_correlator.config import Settings
from opencanary_correlator.constants import KEY_INCIDENTS
from opencanary_correlator.core.retention import RetentionJanitor
from opencanary_correlator.storage.keys import (
    INCIDENTS_CREATED,
    OUTBOX_DEAD,
    OUTBOX_INDEX,
    incident_latest_key,
    outbox_alert_key,
    outbox_envelope_key,
)

NOW = 1_800_000_000.0
OLD = NOW - 40 * 86400
INCIDENT = "incident:ftplogin:10.0.0.5:1000"
POINTER = incident_latest_key("ftp.login_attempt", "10.0.0.5")


async def seed_incident(store: Any, *, key: str = INCIDENT, score: float = OLD) -> None:
    await store.hset_mapping(key, {"src_host": "10.0.0.5", "created": str(int(score))})
    await store.client.zadd(KEY_INCIDENTS, {key: score})


def janitor(store: Any, settings: Settings, audit: Any) -> RetentionJanitor:
    return RetentionJanitor(store, settings, audit, clock=lambda: NOW)


async def test_retention_does_nothing_unless_it_is_enabled(
    store: Any, settings_factory: Any, audit: Any
) -> None:
    await seed_incident(store)

    summary = await janitor(store, settings_factory(), audit).run_once()

    assert summary["incidents"] == 0
    assert await store.hgetall(INCIDENT)


async def test_an_old_incident_is_removed_with_its_index_pointer_and_creation(
    store: Any, settings_factory: Any, audit: Any
) -> None:
    await seed_incident(store)
    await store.hset_mapping(POINTER, {"key": INCIDENT, "score": str(int(OLD))})
    await store.client.zadd(INCIDENTS_CREATED, {INCIDENT: OLD})

    summary = await janitor(store, settings_factory(retention_enabled=True), audit).run_once()

    assert summary["incidents"] == 1
    assert await store.hgetall(INCIDENT) == {}
    assert await store.client.zscore(KEY_INCIDENTS, INCIDENT) is None
    assert await store.client.exists(POINTER) == 0
    assert await store.client.zscore(INCIDENTS_CREATED, INCIDENT) is None


async def test_a_recent_incident_is_kept(store: Any, settings_factory: Any, audit: Any) -> None:
    await seed_incident(store, score=NOW - 3600)

    summary = await janitor(store, settings_factory(retention_enabled=True), audit).run_once()

    assert summary["incidents"] == 0
    assert await store.hgetall(INCIDENT)


async def test_a_pointer_to_a_newer_incident_is_not_deleted(
    store: Any, settings_factory: Any, audit: Any
) -> None:
    await seed_incident(store)
    newer = "incident:ftplogin:10.0.0.5:2000"
    await store.hset_mapping(POINTER, {"key": newer, "score": str(int(NOW))})

    await janitor(store, settings_factory(retention_enabled=True), audit).run_once()

    assert await store.client.hget(POINTER, "key") == newer


@pytest.mark.parametrize("state", ["preparing", "ready"])
async def test_an_owed_delivery_protects_its_incident(
    store: Any, settings_factory: Any, audit: Any, state: str
) -> None:
    await seed_incident(store)
    await store.hset_mapping(
        outbox_envelope_key(INCIDENT), {"state": state, "targets": "telegram:abc"}
    )
    index = OUTBOX_INDEX if state == "ready" else "outbox:v2:preparing"
    await store.client.zadd(index, {f"{INCIDENT}#telegram:abc": NOW})

    summary = await janitor(store, settings_factory(retention_enabled=True), audit).run_once()

    assert summary["protected"] == 1
    assert await store.hgetall(INCIDENT)


async def test_a_dead_letter_protects_its_incident_until_the_dlq_expires(
    store: Any, settings_factory: Any, audit: Any
) -> None:
    await seed_incident(store)
    entry = f"{INCIDENT}#telegram:abc"
    await store.hset_mapping(
        outbox_envelope_key(INCIDENT), {"state": "ready", "targets": "telegram:abc"}
    )
    await store.client.zadd(OUTBOX_DEAD, {entry: NOW - 3600})

    summary = await janitor(store, settings_factory(retention_enabled=True), audit).run_once()

    assert summary["protected"] == 1
    assert await store.hgetall(INCIDENT)


async def test_old_dead_letters_expire_and_fresh_ones_survive(
    store: Any, settings_factory: Any, audit: Any
) -> None:
    expired, fresh = "one#telegram:abc", "two#telegram:abc"
    await store.hset_mapping(outbox_alert_key(expired), {"state": "dead", "attempts": "8"})
    await store.hset_mapping(outbox_alert_key(fresh), {"state": "dead", "attempts": "8"})
    await store.client.zadd(OUTBOX_DEAD, {expired: NOW - 20 * 86400, fresh: NOW - 3600})

    summary = await janitor(store, settings_factory(retention_enabled=True), audit).run_once()

    assert summary["dead"] == 1
    assert await store.client.zscore(OUTBOX_DEAD, expired) is None
    assert await store.hgetall(outbox_alert_key(expired)) == {}
    assert await store.client.zscore(OUTBOX_DEAD, fresh) is not None


async def test_replay_requeues_a_dead_letter_exactly_once(store: Any) -> None:
    entry = "one#telegram:abc"
    await store.hset_mapping(
        outbox_alert_key(entry), {"state": "dead", "attempts": "8", "last_error": "503"}
    )
    await store.client.zadd(OUTBOX_DEAD, {entry: NOW - 60})

    assert await store.replay_dead_letter(entry, now=NOW, retention=604800) is True
    fields = await store.hgetall(outbox_alert_key(entry))
    assert fields["state"] == "ready"
    assert fields["attempts"] == "0"
    assert await store.client.zscore(OUTBOX_DEAD, entry) is None
    assert await store.client.zscore(OUTBOX_INDEX, entry) is not None
    # A second replay is a no-op: the entry is no longer in the dead list.
    assert await store.replay_dead_letter(entry, now=NOW, retention=604800) is False


async def test_listing_dead_letters_is_read_only_and_omits_payloads(store: Any) -> None:
    entry = "one#telegram:abc"
    await store.hset_mapping(
        outbox_alert_key(entry),
        {
            "state": "dead",
            "attempts": "8",
            "last_error": "503",
            "incident": INCIDENT,
            "target": "telegram:abc",
            "payload": "secret",
        },
    )
    await store.client.zadd(OUTBOX_DEAD, {entry: NOW - 60})

    listed = await store.dead_letters(limit=10)

    assert listed[0]["entry"] == entry
    assert listed[0]["last_error"] == "503"
    assert "payload" not in listed[0]
    assert await store.client.zscore(OUTBOX_DEAD, entry) is not None


def test_a_dlq_that_outlives_incidents_is_refused(settings_factory: Any) -> None:
    with pytest.raises(ValidationError, match="OCC_DLQ_RETENTION_DAYS"):
        settings_factory(retention_enabled=True, retention_days=7, dlq_retention_days=7)


def test_retention_is_off_by_default(settings_factory: Any) -> None:
    settings = settings_factory()

    assert settings.retention_enabled is False
    assert settings.dlq_retention_days < settings.retention_days


def test_admin_flags_are_mutually_exclusive() -> None:
    with pytest.raises(SystemExit):
        build_parser().parse_args(["--dlq-list", "--retention-run"])
