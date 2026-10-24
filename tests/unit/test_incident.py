"""Incident models, legacy report formatting and atomic create-or-merge."""

from __future__ import annotations

import json

import pytest

from opencanary_correlator.core.incident import (
    IncidentFTPLogin,
    IncidentHostPortScan,
    IncidentNetworkPortScan,
    IncidentRepository,
    IncidentSMBFileOpen,
)
from opencanary_correlator.schemas import CanaryEvent
from opencanary_correlator.storage.keys import incident_latest_key


def make_incident(incident_cls=IncidentFTPLogin, **overrides):
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


def test_smb_report_without_logdata_falls_back_to_the_base_report() -> None:
    incident = make_incident(IncidentSMBFileOpen, logdata=None)

    assert "Shared File Opened" in incident.format_report()
    assert "EXTRA" not in incident.format_report()


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
    repository, store, clock, event_factory
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
    repository, store, clock, event_factory
) -> None:
    created = await repository.record(
        "ftp.login_attempt", CanaryEvent.model_validate(event_factory())
    )
    assert created is not None

    pointer = await store.hgetall(incident_latest_key("ftp.login_attempt", "10.0.0.5"))

    assert pointer == {"key": created.key, "score": str(int(clock.now))}


async def test_merge_falls_back_to_the_index_when_the_pointer_is_missing(
    repository, store, clock, event_factory
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
    repository, store, clock, event_factory
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
    repository, store, clock, event_factory
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
    repository, store, clock, event_factory
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


async def test_new_incident_after_the_horizon(repository, clock, event_factory) -> None:
    event = CanaryEvent.model_validate(event_factory())

    first = await repository.record("ftp.login_attempt", event)
    assert first is not None
    clock.advance(61)

    second = await repository.record("ftp.login_attempt", event)

    assert second is not None
    assert second.key != first.key


async def test_per_incident_horizon_extends_the_merge_window(
    store, settings_factory, audit, clock, event_factory
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


async def test_incidents_are_per_source_host(repository, event_factory) -> None:
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
    repository, event_factory, longer_host, shorter_host
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


async def test_host_portscan_merges_distinct_ports(repository, store, clock, event_factory) -> None:
    event = CanaryEvent.model_validate(event_factory(logtype=5001, logdata={}))

    created = await repository.record("scans.host_portscan", event, logdata=[21, 22], logtype=5003)
    assert created is not None
    assert created.logtype == 5003

    clock.advance(5)
    await repository.record("scans.host_portscan", event, logdata=[22, 23], logtype=5003)

    fields = await store.hgetall(created.key)
    assert json.loads(fields["logdata"]) == [21, 22, 23]


async def test_network_portscan_merges_targets(repository, store, clock, event_factory) -> None:
    event = CanaryEvent.model_validate(event_factory(logtype=5001, logdata={}))

    created = await repository.record(
        "scans.network_portscan", event, logdata=["10.0.0.2"], logtype=5002
    )
    assert created is not None
    clock.advance(5)
    await repository.record("scans.network_portscan", event, logdata=["10.0.0.3"], logtype=5002)

    fields = await store.hgetall(created.key)
    assert json.loads(fields["logdata"]) == ["10.0.0.2", "10.0.0.3"]


async def test_incident_classes_are_registered() -> None:
    from opencanary_correlator.core.incident import INCIDENT_TYPES

    assert set(INCIDENT_TYPES) == {
        "ftp.login_attempt",
        "http.login_attempt",
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
