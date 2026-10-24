"""Read-side queries keep the JSON shape the legacy console consumes."""

from __future__ import annotations

import json

from opencanary_correlator.constants import KEY_INCIDENTS
from opencanary_correlator.core.incident import IncidentRepository
from opencanary_correlator.schemas import CanaryEvent
from opencanary_correlator.storage.keys import device_key
from opencanary_correlator.storage.queries import (
    clear_incidents,
    get_acknowledged_incidents,
    get_all_incidents,
    get_console_setting,
    get_device,
    get_incident,
    get_logs,
    get_unacknowledged_incidents,
    set_console_setting,
    should_notify,
    write_log,
)


async def create_incident(store, settings_factory, audit, clock, event_factory, **overrides):
    repository = IncidentRepository(store, settings_factory(), audit, clock=clock)
    event = CanaryEvent.model_validate(event_factory(**overrides))
    incident = await repository.record("ftp.login_attempt", event)
    assert incident is not None
    return incident


async def test_incident_json_shape_matches_the_console(
    store, settings_factory, audit, clock, event_factory
) -> None:
    incident = await create_incident(store, settings_factory, audit, clock, event_factory)

    payloads = await get_all_incidents(store)

    assert len(payloads) == 1
    payload = payloads[0]
    assert payload["key"] == incident.key
    assert payload["created"] == str(incident.created)
    assert isinstance(payload["created_printable"], str)
    assert isinstance(payload["created_age_seconds"], float)
    assert payload["events_list"] == [incident.created * 1000]
    assert payload["logdata"] == [{"USERNAME": "admin", "PASSWORD": "hunter2"}]
    assert payload["host"] == {}
    assert payload["acknowledged"] == "False"


async def test_incidents_can_be_filtered_by_node(
    store, settings_factory, audit, clock, event_factory
) -> None:
    await create_incident(store, settings_factory, audit, clock, event_factory, node_id="a")
    await create_incident(
        store, settings_factory, audit, clock, event_factory, node_id="b", src_host="10.0.0.6"
    )

    payloads = await get_all_incidents(store, node_id="b", include_hosts=False)

    assert [payload["node_id"] for payload in payloads] == ["b"]
    assert "host" not in payloads[0]


async def test_acknowledged_filters(store, settings_factory, audit, clock, event_factory) -> None:
    incident = await create_incident(store, settings_factory, audit, clock, event_factory)

    assert len(await get_unacknowledged_incidents(store)) == 1
    assert await get_acknowledged_incidents(store) == []

    fields = await store.hgetall(incident.key)
    await store.save_incident(
        incident.key,
        {**fields, "acknowledged": "True"},
        score=float(fields["created"]),
    )

    assert await get_unacknowledged_incidents(store) == []
    assert len(await get_acknowledged_incidents(store)) == 1


async def test_events_are_capped_at_one_hundred(
    store, settings_factory, audit, clock, event_factory
) -> None:
    incident = await create_incident(store, settings_factory, audit, clock, event_factory)
    fields = await store.hgetall(incident.key)
    fields["events_list"] = ",".join(str(incident.created + offset) for offset in range(150))
    await store.save_incident(incident.key, fields, score=float(fields["created"]))

    payload = (await get_all_incidents(store, include_hosts=False))[0]

    assert len(payload["events_list"]) == 100
    assert payload["events_skipped"] == 50


async def test_get_incident_returns_none_when_missing(store) -> None:
    assert await get_incident(store, "incident:ftplogin:nope:1") is None


async def test_clear_incidents_removes_hashes_and_index(
    store, settings_factory, audit, clock, event_factory
) -> None:
    incident = await create_incident(store, settings_factory, audit, clock, event_factory)

    removed = await clear_incidents(store)

    assert removed == 1
    assert await store.hgetall(incident.key) == {}
    assert await store.zrangebyscore(KEY_INCIDENTS, "-inf", "+inf") == []


async def test_logs_are_bounded_and_newest_first(store) -> None:
    for index in range(5):
        await write_log(store, f"line-{index}", max_entries=3)

    assert await get_logs(store) == ["line-4", "line-3", "line-2"]
    assert await get_logs(store, limit=1) == ["line-4"]


async def test_console_settings_round_trip(store) -> None:
    assert await get_console_setting(store, "theme") is None
    assert await get_console_setting(store, "theme", "dark") == "dark"

    await set_console_setting(store, "theme", "light")

    assert await get_console_setting(store, "theme") == "light"


async def test_device_queries(store, settings_factory, audit, clock, event_factory) -> None:
    incident = await create_incident(store, settings_factory, audit, clock, event_factory)
    assert await get_device(store, "canary-1") is None
    assert await should_notify(store, "canary-1") is True

    await store.hset_mapping(
        device_key("canary-1"),
        {"node_id": "canary-1", "ignore_notifications_general": "True"},
    )

    device = await get_device(store, "canary-1")

    assert device is not None
    assert device["node_id"] == "canary-1"
    assert [entry["key"] for entry in device["unacknowleged_incidents"]] == [incident.key]
    assert await should_notify(store, "canary-1") is False


async def test_events_skipped_is_derived_from_the_exact_counter(
    store, settings_factory, audit, clock, event_factory
) -> None:
    """Storage is capped, so the skipped count must come from `events_count`."""
    incident = await create_incident(store, settings_factory, audit, clock, event_factory)
    fields = await store.hgetall(incident.key)
    fields["events_list"] = ",".join(str(incident.created + offset) for offset in range(100))
    fields["events_count"] = "10000"
    fields["events_truncated"] = "True"
    await store.save_incident(incident.key, fields, score=float(fields["created"]))

    payload = (await get_all_incidents(store, include_hosts=False))[0]

    assert len(payload["events_list"]) == 100
    assert payload["events_skipped"] == 9900
    assert payload["events_truncated"] is True


async def test_incidents_without_the_counter_keep_the_legacy_skip_calculation(
    store, settings_factory, audit, clock, event_factory
) -> None:
    incident = await create_incident(store, settings_factory, audit, clock, event_factory)
    fields = await store.hgetall(incident.key)
    fields["events_list"] = ",".join(str(incident.created + offset) for offset in range(150))
    await store.save_incident(incident.key, fields, score=float(fields["created"]))
    await store.client.hdel(incident.key, "events_count")

    payload = (await get_all_incidents(store, include_hosts=False))[0]

    assert payload["events_skipped"] == 50


async def test_logdata_is_truncated_for_the_console(
    store, settings_factory, audit, clock, event_factory
) -> None:
    incident = await create_incident(store, settings_factory, audit, clock, event_factory)
    fields = await store.hgetall(incident.key)
    fields["logdata"] = json.dumps([{"index": index} for index in range(150)])
    await store.save_incident(incident.key, fields, score=float(fields["created"]))

    payload = (await get_all_incidents(store, include_hosts=False))[0]

    assert len(payload["logdata"]) == 100
