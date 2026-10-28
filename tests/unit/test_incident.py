"""Incident models, legacy report formatting and atomic create-or-merge."""

from __future__ import annotations

import json
import logging
from typing import Any

import pytest

from opencanary_correlator.constants import KEY_INCIDENTS
from opencanary_correlator.core.incident import (
    IncidentFTPLogin,
    IncidentHostPortScan,
    IncidentHTTPRequest,
    IncidentNetworkPortScan,
    IncidentRepository,
    IncidentSMBFileOpen,
)
from opencanary_correlator.schemas import CanaryEvent
from opencanary_correlator.storage.keys import incident_latest_key


def make_incident(incident_cls: Any = IncidentFTPLogin, **overrides: Any) -> Any:
    params = {
        "key": "incident:ftplogin:10.0.0.5:1418997029",
        "node_id": "canary-1",
        "src_host": "10.0.0.5",
        "src_port": 40000,
        "dst_host": "10.0.0.2",
        "dst_port": 21,
        "logtype": 2000,
        "created": 1418997029,
        "events_list": "1418997029",
        "events_count": 1,
        "logdata": json.dumps([{"USERNAME": "admin"}]),
    }
    params.update(overrides)
    return incident_cls(**params)


def test_title_and_short_report_match_the_legacy_text() -> None:
    incident = make_incident()

    assert incident.format_title() == "FTP Login Attempt by 10.0.0.5 on canary-1 (10.0.0.2)"
    assert incident.format_report_short() == (
        "Canary Incident: FTP Login Attempt. Source 10.0.0.5. Target canary-1 (10.0.0.2)."
    )


def test_full_report_matches_the_legacy_layout() -> None:
    report = make_incident().format_report()

    assert report.startswith("\n" + "=" * 70)
    assert "  Incident: FTP Login Attempt" in report
    assert "  Time    : 2014-12-19 13:50:29 (UTC)" in report
    assert "  Source  : 10.0.0.5" in report
    assert "  Target  : 10.0.0.2 (id canary-1)" in report
    assert "EXTRA" not in report


def test_smb_report_includes_file_and_user() -> None:
    incident = make_incident(
        IncidentSMBFileOpen,
        logdata=json.dumps([{"FILENAME": "payroll.xlsx", "USER": "admin"}]),
    )

    assert "  File    : payroll.xlsx" in incident.format_report()
    assert "  User    : admin" in incident.format_report()
    assert 'File "payroll.xlsx", user "admin"' in incident.format_report_short()


def test_http_request_report_shows_the_request_line() -> None:
    incident = make_incident(
        IncidentHTTPRequest,
        logtype=3000,
        dst_port=80,
        logdata=json.dumps(
            [{"METHOD": "GET", "PATH": "/admin", "HOST": "canary-1", "USERAGENT": "curl/8.4.0"}]
        ),
    )

    report = incident.format_report()

    assert "  Incident: HTTP Request" in report
    assert "  Method  : GET" in report
    assert "  Path    : /admin" in report
    assert "  Host    : canary-1" in report
    assert "  Agent   : curl/8.4.0" in report
    assert 'GET "/admin" on canary-1' in incident.format_report_short()


def test_http_request_report_without_logdata_falls_back_to_the_base_report() -> None:
    incident = make_incident(IncidentHTTPRequest, logtype=3000, logdata=None)

    assert "  Incident: HTTP Request" in incident.format_report()
    assert "  Path" not in incident.format_report()
    assert incident.format_report_short() == (
        "Canary Incident: HTTP Request. Source 10.0.0.5. Target canary-1 (10.0.0.2)."
    )


def test_smb_report_without_logdata_falls_back_to_the_base_report() -> None:
    incident = make_incident(IncidentSMBFileOpen, logdata=None)

    assert "Shared File Opened" in incident.format_report()
    assert "EXTRA" not in incident.format_report()


def test_smb_failure_never_logs_the_stored_payload(caplog: Any) -> None:
    """The fallback branch used to log `logdata` raw, which can hold a password."""
    incident = make_incident(IncidentSMBFileOpen, logdata='{"PASSWORD": "hunter2"')

    with caplog.at_level(logging.ERROR, logger="opencanary_correlator.core.incident"):
        report = incident.format_report()

    assert "Shared File Opened" in report
    assert "hunter2" not in caplog.text
    assert incident.key in caplog.text


def test_network_scan_report_lists_targets() -> None:
    incident = make_incident(
        IncidentNetworkPortScan,
        logdata=json.dumps(["10.0.0.2", "10.0.0.3"]),
        logtype=5002,
        dst_port=22,
    )

    report = incident.format_report()

    assert "  Port    : 22" in report
    assert "  Targets : 10.0.0.2, 10.0.0.3" in report


async def test_repository_creates_then_merges_within_horizon(
    repository: Any, store: Any, clock: Any, event_factory: Any
) -> None:
    event = CanaryEvent.model_validate(event_factory())
    first_seen = int(clock.now)

    created = await repository.record("ftp.login_attempt", event)

    assert created is not None
    assert created.key == f"incident:ftplogin:10.0.0.5:{first_seen}"
    assert created.events_count == 1

    clock.advance(10)
    merged = await repository.record("ftp.login_attempt", event)
    assert merged is None

    fields = await store.hgetall(created.key)
    assert fields["events_count"] == "2"
    assert fields["events_list"] == f"{first_seen},{int(clock.now)}"
    assert fields["updated"] == "True"
    assert fields["acknowledged"] == "False"
    assert json.loads(fields["logdata"]) == [
        {"USERNAME": "admin", "PASSWORD": "hunter2"},
        {"USERNAME": "admin", "PASSWORD": "hunter2"},
    ]


async def test_repository_writes_a_per_host_pointer(
    repository: Any, store: Any, clock: Any, event_factory: Any
) -> None:
    created = await repository.record(
        "ftp.login_attempt", CanaryEvent.model_validate(event_factory())
    )
    assert created is not None

    pointer = await store.hgetall(incident_latest_key("ftp.login_attempt", "10.0.0.5"))

    assert pointer == {"key": created.key, "score": str(int(clock.now))}


async def test_merge_falls_back_to_the_index_when_the_pointer_is_missing(
    repository: Any, store: Any, clock: Any, event_factory: Any
) -> None:
    """Incidents created by an older replica still merge during a rolling upgrade."""
    event = CanaryEvent.model_validate(event_factory())
    created = await repository.record("ftp.login_attempt", event)
    assert created is not None
    await store.delete(incident_latest_key("ftp.login_attempt", "10.0.0.5"))

    clock.advance(5)
    assert await repository.record("ftp.login_attempt", event) is None

    fields = await store.hgetall(created.key)
    assert fields["events_count"] == "2"
    pointer = await store.hgetall(incident_latest_key("ftp.login_attempt", "10.0.0.5"))
    assert pointer["key"] == created.key


async def test_stale_pointer_does_not_merge_outside_the_horizon(
    repository: Any, store: Any, clock: Any, event_factory: Any
) -> None:
    event = CanaryEvent.model_validate(event_factory())
    first = await repository.record("ftp.login_attempt", event)
    assert first is not None

    clock.advance(61)
    second = await repository.record("ftp.login_attempt", event)

    assert second is not None
    assert second.key != first.key
    pointer = await store.hgetall(incident_latest_key("ftp.login_attempt", "10.0.0.5"))
    assert pointer["key"] == second.key


async def test_pointer_to_a_deleted_incident_creates_a_new_one(
    repository: Any, store: Any, clock: Any, event_factory: Any
) -> None:
    """An operator may delete an incident hash; the next event must not crash."""
    event = CanaryEvent.model_validate(event_factory())
    first = await repository.record("ftp.login_attempt", event)
    assert first is not None
    await store.delete(first.key)

    clock.advance(5)
    second = await repository.record("ftp.login_attempt", event)

    assert second is not None
    pointer = await store.hgetall(incident_latest_key("ftp.login_attempt", "10.0.0.5"))
    assert pointer["key"] == second.key


async def test_corrupt_pointer_falls_back_to_the_index(
    repository: Any, store: Any, clock: Any, event_factory: Any
) -> None:
    event = CanaryEvent.model_validate(event_factory())
    created = await repository.record("ftp.login_attempt", event)
    assert created is not None
    await store.hset_mapping(
        incident_latest_key("ftp.login_attempt", "10.0.0.5"),
        {"key": "incident:ftplogin:10.0.0.5:1", "score": "not-a-number"},
    )

    clock.advance(5)
    assert await repository.record("ftp.login_attempt", event) is None

    fields = await store.hgetall(created.key)
    assert fields["events_count"] == "2"


async def test_new_incident_after_the_horizon(
    repository: Any, clock: Any, event_factory: Any
) -> None:
    event = CanaryEvent.model_validate(event_factory())

    first = await repository.record("ftp.login_attempt", event)
    assert first is not None
    clock.advance(61)

    second = await repository.record("ftp.login_attempt", event)

    assert second is not None
    assert second.key != first.key


async def test_per_incident_horizon_extends_the_merge_window(
    store: Any, settings_factory: Any, audit: Any, clock: Any, event_factory: Any
) -> None:
    settings = settings_factory(incident_horizons={"ftp.login_attempt": 120})
    repository = IncidentRepository(store, settings, audit, clock=clock)
    event = CanaryEvent.model_validate(event_factory())

    created = await repository.record("ftp.login_attempt", event)
    assert created is not None

    clock.advance(61)

    assert await repository.record("ftp.login_attempt", event) is None
    fields = await store.hgetall(created.key)
    assert fields["events_count"] == "2"

    clock.advance(121)

    later = await repository.record("ftp.login_attempt", event)
    assert later is not None
    assert later.key != created.key


async def test_incidents_are_per_source_host(repository: Any, event_factory: Any) -> None:
    first = await repository.record(
        "ftp.login_attempt",
        CanaryEvent.model_validate(event_factory(src_host="10.0.0.5")),
    )
    second = await repository.record(
        "ftp.login_attempt",
        CanaryEvent.model_validate(event_factory(src_host="10.0.0.6")),
    )

    assert first is not None and second is not None
    assert first.key != second.key


@pytest.mark.parametrize(
    ("longer_host", "shorter_host"),
    [
        ("10.0.0.55", "10.0.0.5"),
        ("web01", "web"),
        ("::10", "::1"),
    ],
)
async def test_hosts_sharing_a_prefix_do_not_merge(
    repository: Any, event_factory: Any, longer_host: Any, shorter_host: Any
) -> None:
    longer = await repository.record(
        "ftp.login_attempt",
        CanaryEvent.model_validate(event_factory(src_host=longer_host)),
    )
    shorter = await repository.record(
        "ftp.login_attempt",
        CanaryEvent.model_validate(event_factory(src_host=shorter_host)),
    )

    assert longer is not None
    assert shorter is not None
    assert longer.key.startswith(f"incident:ftplogin:{longer_host}:")
    assert shorter.key.startswith(f"incident:ftplogin:{shorter_host}:")
    assert longer.key != shorter.key


async def test_host_portscan_merges_distinct_ports(
    repository: Any, store: Any, clock: Any, event_factory: Any
) -> None:
    event = CanaryEvent.model_validate(event_factory(logtype=5001, logdata={}))

    created = await repository.record("scans.host_portscan", event, logdata=[21, 22], logtype=5003)
    assert created is not None
    assert created.logtype == 5003

    clock.advance(5)
    await repository.record("scans.host_portscan", event, logdata=[22, 23], logtype=5003)

    fields = await store.hgetall(created.key)
    assert json.loads(fields["logdata"]) == [21, 22, 23]


async def test_network_portscan_merges_targets(
    repository: Any, store: Any, clock: Any, event_factory: Any
) -> None:
    event = CanaryEvent.model_validate(event_factory(logtype=5001, logdata={}))

    created = await repository.record(
        "scans.network_portscan", event, logdata=["10.0.0.2"], logtype=5002
    )
    assert created is not None
    clock.advance(5)
    await repository.record("scans.network_portscan", event, logdata=["10.0.0.3"], logtype=5002)

    fields = await store.hgetall(created.key)
    assert json.loads(fields["logdata"]) == ["10.0.0.2", "10.0.0.3"]


async def test_small_incidents_keep_the_legacy_field_set(
    repository: Any, store: Any, clock: Any, event_factory: Any
) -> None:
    created = await repository.record(
        "ftp.login_attempt", CanaryEvent.model_validate(event_factory())
    )
    assert created is not None

    fields = await store.hgetall(created.key)

    assert "events_truncated" not in fields


async def test_merge_caps_stored_events_and_keeps_the_exact_count(
    repository: Any, store: Any, clock: Any, event_factory: Any
) -> None:
    event = CanaryEvent.model_validate(event_factory())
    created = await repository.record("ftp.login_attempt", event)
    assert created is not None

    for _ in range(249):
        assert await repository.record("ftp.login_attempt", event) is None

    fields = await store.hgetall(created.key)

    assert fields["events_count"] == "250"
    assert len(fields["events_list"].split(",")) == 100
    assert len(json.loads(fields["logdata"])) == 100
    assert fields["events_truncated"] == "True"
    # A login entry is ~45 bytes, so 100 of them plus 100 timestamps is the
    # constant ceiling: the hash no longer depends on the incident's age.
    assert sum(len(name) + len(value) for name, value in fields.items()) < 8192


async def test_merge_after_the_cap_does_not_rewrite_stored_history(
    repository: Any, store: Any, clock: Any, event_factory: Any
) -> None:
    event = CanaryEvent.model_validate(event_factory())
    created = await repository.record("ftp.login_attempt", event)
    assert created is not None
    for _ in range(149):
        await repository.record("ftp.login_attempt", event)

    before = await store.hgetall(created.key)
    for _ in range(10):
        await repository.record("ftp.login_attempt", event)
    after = await store.hgetall(created.key)

    assert after["events_list"] == before["events_list"]
    assert after["logdata"] == before["logdata"]
    assert int(after["events_count"]) == int(before["events_count"]) + 10


async def test_capped_merge_writes_only_the_counters(
    repository: Any, store: Any, clock: Any, event_factory: Any, monkeypatch: Any
) -> None:
    """A capped incident must not send its stored history back to Redis."""
    event = CanaryEvent.model_validate(event_factory())
    created = await repository.record("ftp.login_attempt", event)
    assert created is not None
    for _ in range(150):
        await repository.record("ftp.login_attempt", event)

    captured: list[dict[str, str]] = []
    original = store.save_incident

    async def spy(key: Any, fields: Any, *, score: Any, pointer_key: Any = None) -> None:
        captured.append(dict(fields))
        await original(key, fields, score=score, pointer_key=pointer_key)

    monkeypatch.setattr(store, "save_incident", spy)
    await repository.record("ftp.login_attempt", event)

    assert len(captured) == 1
    assert set(captured[0]) <= {"events_count", "events_truncated", "updated"}


async def test_frozen_incident_merges_without_decoding_its_logdata(
    store: Any, settings_factory: Any, audit: Any, clock: Any, event_factory: Any
) -> None:
    """A full incident must not pay for a decode whose result is discarded."""
    repository = IncidentRepository(
        store, settings_factory(max_stored_events=2), audit, clock=clock
    )
    event = CanaryEvent.model_validate(event_factory())
    created = await repository.record("ftp.login_attempt", event)
    assert created is not None
    # The cap holds timestamps, so it is full one event before the count exceeds it.
    clock.advance(1)
    await repository.record("ftp.login_attempt", event)
    clock.advance(1)
    await repository.record("ftp.login_attempt", event)

    frozen = await store.hgetall(created.key)
    assert frozen["events_truncated"] == "True"
    # Deliberately unparseable: a merge that decodes the stored list would raise,
    # and the stored bytes must survive untouched either way.
    await store.hset_mapping(created.key, {"logdata": "[not json"})

    clock.advance(5)
    assert await repository.record("ftp.login_attempt", event) is None

    fields = await store.hgetall(created.key)
    assert fields["events_count"] == "4"
    assert fields["logdata"] == "[not json"
    assert fields["events_list"] == frozen["events_list"]
    assert fields["events_truncated"] == "True"


async def test_raising_the_cap_lets_a_frozen_incident_record_again(
    store: Any, settings_factory: Any, audit: Any, clock: Any, event_factory: Any
) -> None:
    """`OCC_MAX_STORED_EVENTS` is a knob, so a raised cap must resume history."""
    event = CanaryEvent.model_validate(event_factory())
    narrow = IncidentRepository(store, settings_factory(max_stored_events=2), audit, clock=clock)
    created = await narrow.record("ftp.login_attempt", event)
    assert created is not None
    clock.advance(1)
    await narrow.record("ftp.login_attempt", event)
    clock.advance(1)
    await narrow.record("ftp.login_attempt", event)
    frozen = await store.hgetall(created.key)
    assert frozen["events_truncated"] == "True"

    clock.advance(5)
    wide = IncidentRepository(store, settings_factory(max_stored_events=5), audit, clock=clock)
    assert await wide.record("ftp.login_attempt", event) is None

    fields = await store.hgetall(created.key)
    assert fields["events_list"] == f"{frozen['events_list']},{int(clock.now)}"
    assert len(json.loads(fields["logdata"])) == 3
    assert fields["events_count"] == "4"
    assert fields["events_truncated"] == "True"


async def test_frozen_scan_still_merges_its_logdata(
    store: Any, settings_factory: Any, audit: Any, clock: Any, event_factory: Any
) -> None:
    """Scan evidence is set-shaped: freezing timestamps must not freeze it."""
    repository = IncidentRepository(
        store, settings_factory(max_stored_events=2), audit, clock=clock
    )
    event = CanaryEvent.model_validate(event_factory(logtype=5001, logdata={}))
    created = await repository.record("scans.host_portscan", event, logdata=[1, 2], logtype=5003)
    assert created is not None
    clock.advance(5)
    await repository.record("scans.host_portscan", event, logdata=[3], logtype=5003)
    clock.advance(5)
    await repository.record("scans.host_portscan", event, logdata=[4], logtype=5003)

    fields = await store.hgetall(created.key)

    assert fields["events_truncated"] == "True"
    assert json.loads(fields["logdata"]) == [1, 2, 3, 4]


async def test_scan_logdata_keeps_every_distinct_member(
    repository: Any, store: Any, clock: Any, event_factory: Any
) -> None:
    """Scan evidence is set-shaped, not per-event: it must not be truncated."""
    event = CanaryEvent.model_validate(event_factory(logtype=5001, logdata={}))
    created = await repository.record(
        "scans.host_portscan", event, logdata=list(range(1, 151)), logtype=5003
    )
    assert created is not None

    clock.advance(5)
    await repository.record(
        "scans.host_portscan", event, logdata=list(range(151, 301)), logtype=5003
    )

    fields = await store.hgetall(created.key)

    assert json.loads(fields["logdata"]) == list(range(1, 301))
    assert fields["events_count"] == "2"


async def test_create_keeps_scan_logdata_exact(
    repository: Any, store: Any, clock: Any, event_factory: Any
) -> None:
    event = CanaryEvent.model_validate(event_factory(logtype=5001, logdata={}))

    created = await repository.record(
        "scans.host_portscan", event, logdata=list(range(1, 301)), logtype=5003
    )
    assert created is not None

    fields = await store.hgetall(created.key)

    assert json.loads(fields["logdata"]) == list(range(1, 301))


async def seed_index(store: Any, *, count: int, score: float) -> None:
    """Put `count` incidents for other source hosts inside the horizon."""
    await store.client.zadd(
        KEY_INCIDENTS,
        {f"incident:ftplogin:10.9.0.{index}:{int(score)}": score for index in range(count)},
    )


async def test_fallback_scan_is_bounded_by_the_setting(
    store: Any, settings_factory: Any, audit: Any, audit_stream: Any, clock: Any, event_factory: Any
) -> None:
    """The index scan must not transfer every live incident (O(index) lookup)."""
    settings = settings_factory(incident_lookup_scan_limit=20)
    repository = IncidentRepository(store, settings, audit, clock=clock)
    await seed_index(store, count=200, score=clock.now)

    created = await repository.record(
        "ftp.login_attempt", CanaryEvent.model_validate(event_factory())
    )

    assert created is not None
    records = [json.loads(line) for line in audit_stream.getvalue().splitlines()]
    truncated = [record for record in records if record["action"] == "incident_lookup_truncated"]
    assert truncated == []


async def test_match_inside_the_cap_still_merges(
    store: Any, settings_factory: Any, audit: Any, clock: Any, event_factory: Any
) -> None:
    """A capped scan still finds the host's incident when it is inside the cap."""
    settings = settings_factory(incident_lookup_scan_limit=60)
    repository = IncidentRepository(store, settings, audit, clock=clock)
    event = CanaryEvent.model_validate(event_factory())
    created = await repository.record("ftp.login_attempt", event)
    assert created is not None
    await store.delete(incident_latest_key("ftp.login_attempt", "10.0.0.5"))
    clock.advance(1)
    await seed_index(store, count=50, score=clock.now)

    assert await repository.record("ftp.login_attempt", event) is None

    fields = await store.hgetall(created.key)
    assert fields["events_count"] == "2"


async def test_match_beyond_the_cap_still_merges(
    store: Any, settings_factory: Any, audit: Any, audit_stream: Any, clock: Any, event_factory: Any
) -> None:
    """A pointerless incident behind the cap must merge, not duplicate the alert."""
    settings = settings_factory(incident_lookup_scan_limit=60)
    repository = IncidentRepository(store, settings, audit, clock=clock)
    event = CanaryEvent.model_validate(event_factory())
    created = await repository.record("ftp.login_attempt", event)
    assert created is not None
    await store.delete(incident_latest_key("ftp.login_attempt", "10.0.0.5"))
    clock.advance(1)
    await seed_index(store, count=70, score=clock.now)

    assert await repository.record("ftp.login_attempt", event) is None

    fields = await store.hgetall(created.key)
    assert fields["events_count"] == "2"
    actions = [json.loads(line)["action"] for line in audit_stream.getvalue().splitlines()]
    assert "incident_lookup_truncated" not in actions


async def test_new_host_beyond_a_full_index_creates_one_incident(
    store: Any, settings_factory: Any, audit: Any, clock: Any, event_factory: Any
) -> None:
    """A genuinely new host still gets its incident after a full-horizon miss."""
    settings = settings_factory(incident_lookup_scan_limit=20)
    repository = IncidentRepository(store, settings, audit, clock=clock)
    await seed_index(store, count=200, score=clock.now)

    created = await repository.record(
        "ftp.login_attempt", CanaryEvent.model_validate(event_factory())
    )

    assert created is not None
    assert await store.client.zcard(KEY_INCIDENTS) == 201


async def test_a_live_pointer_answers_without_scanning(store: Any, clock: Any) -> None:
    await seed_index(store, count=500, score=clock.now)
    pointer_key = incident_latest_key("ftp.login_attempt", "10.0.0.5")
    pointed = "incident:ftplogin:10.0.0.5:1700000000"
    await store.hset_mapping(pointer_key, {"key": pointed, "score": str(int(clock.now))})

    lookup = await store.find_recent_incident(
        "incident:ftplogin:10.0.0.5:",
        min_score=clock.now - 60,
        pointer_key=pointer_key,
        scan_limit=10,
    )

    assert lookup.key == pointed
    assert lookup.scanned == 0
    assert lookup.truncated is False


async def test_incident_classes_are_registered() -> None:
    from opencanary_correlator.core.incident import INCIDENT_TYPES

    assert set(INCIDENT_TYPES) == {
        "ftp.login_attempt",
        "http.login_attempt",
        "http.request",
        "ssh.login_attempt",
        "telnet.login_attempt",
        "httpproxy.login_attempt",
        "mysql.login_attempt",
        "mssql.login_attempt",
        "tftp.action",
        "ntp.monlist",
        "vnc.login_attempt",
        "snmp.cmd",
        "rdp.login_attempt",
        "sip.login_attempt",
        "smb.file_open",
        "scans.host_portscan",
        "scans.network_portscan",
    }
    assert INCIDENT_TYPES["scans.host_portscan"] is IncidentHostPortScan
