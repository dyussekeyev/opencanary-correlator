"""Validation tests for canary events: real payloads accepted, hostile ones rejected."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from opencanary_correlator.constants import DEFAULT_EVENT_FIELDS, LogType
from opencanary_correlator.schemas import (
    CanaryEvent,
    FtpLoginData,
    HttpLoginData,
    IncidentRecord,
    SmbFileOpenData,
    SshLoginData,
    UserData,
)

RECEIVED_AT = datetime(2026, 10, 24, 12, 0, tzinfo=UTC)


# --- Accepted real-world payloads -------------------------------------------


def test_accepts_payload_produced_by_sanitize_log(event_factory: Any) -> None:
    event = CanaryEvent.model_validate(event_factory())

    assert event.logtype is LogType.LOG_FTP_LOGIN_ATTEMPT
    assert event.src_host == "10.0.0.5"
    assert event.src_port == 4444
    assert event.dst_port == 21
    assert event.node_id == "canary-1"
    assert event.resolved_time(RECEIVED_AT) == datetime(2026, 10, 24, 10, 0, tzinfo=UTC)


def test_accepts_empty_hosts_and_canary_port_defaults(event_factory: Any) -> None:
    event = CanaryEvent.model_validate(
        event_factory(src_host="", dst_host="", src_port=-1, dst_port=-1)
    )

    assert event.src_host == ""
    assert event.src_port == -1
    assert event.dst_port == -1


@pytest.mark.parametrize(
    "src_host",
    ["canary.internal", "fe80::1", "2001:db8::dead:beef", "10.0.0.5"],
)
def test_accepts_hostnames_and_ipv6(event_factory: Any, src_host: str) -> None:
    event = CanaryEvent.model_validate(event_factory(src_host=src_host))

    assert event.src_host == src_host


def test_missing_optional_fields_fall_back_to_legacy_defaults() -> None:
    event = CanaryEvent.model_validate({"node_id": "canary-9"})

    assert event.src_host == DEFAULT_EVENT_FIELDS["src_host"]
    assert event.src_port == DEFAULT_EVENT_FIELDS["src_port"]
    assert event.dst_host == DEFAULT_EVENT_FIELDS["dst_host"]
    assert event.dst_port == DEFAULT_EVENT_FIELDS["dst_port"]
    assert event.logdata == DEFAULT_EVENT_FIELDS["logdata"]
    assert event.logtype is LogType.LOG_BASE_MSG


def test_unknown_fields_are_preserved(event_factory: Any) -> None:
    event = CanaryEvent.model_validate(event_factory(custom_field="kept", counter=3))

    assert event.model_extra == {"custom_field": "kept", "counter": 3}


def test_unknown_logtype_is_accepted_but_flagged(event_factory: Any) -> None:
    event = CanaryEvent.model_validate(event_factory(logtype=77777))

    assert event.logtype == 77777
    assert event.is_known_logtype is False


def test_non_object_logdata_is_preserved_under_raw() -> None:
    event = CanaryEvent.model_validate({"node_id": "n1", "logdata": "GET / HTTP/1.0"})

    assert event.logdata == {"raw": "GET / HTTP/1.0"}


def test_none_logdata_becomes_empty_object() -> None:
    event = CanaryEvent.model_validate({"node_id": "n1", "logdata": None})

    assert event.logdata == {}


def test_list_logdata_is_preserved_under_raw() -> None:
    event = CanaryEvent.model_validate({"node_id": "n1", "logdata": [1, "two"]})

    assert event.logdata == {"raw": [1, "two"]}


def test_absent_reported_dst_host_stays_none(event_factory: Any) -> None:
    event = CanaryEvent.model_validate(event_factory())

    assert event.reported_dst_host is None


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("2026-10-24T10:00:00Z", datetime(2026, 10, 24, 10, 0, tzinfo=UTC)),
        ("2026-10-24 10:00:00.123456", datetime(2026, 10, 24, 10, 0, 0, 123456, tzinfo=UTC)),
        (1418997029.99, datetime(2014, 12, 19, 13, 50, 29, 990000, tzinfo=UTC)),
    ],
)
def test_timestamp_shapes_are_parsed(raw: Any, expected: datetime) -> None:
    event = CanaryEvent.model_validate({"node_id": "n1", "local_time": raw})

    assert event.local_time == expected


@pytest.mark.parametrize("raw", ["not-a-date", "", -1, True, None])
def test_unparsable_timestamp_falls_back_to_receipt_time(raw: Any) -> None:
    event = CanaryEvent.model_validate({"node_id": "n1", "local_time": raw})

    assert event.local_time is None
    assert event.resolved_time(RECEIVED_AT) == RECEIVED_AT


def test_utc_time_is_used_when_local_time_is_absent() -> None:
    event = CanaryEvent.model_validate({"node_id": "n1", "utc_time": "2026-10-24 09:00:00.000000"})

    assert event.resolved_time(RECEIVED_AT) == datetime(2026, 10, 24, 9, 0, tzinfo=UTC)


# --- Hostile payloads -------------------------------------------------------


def nested_logdata(depth: int) -> dict[str, Any]:
    payload: dict[str, Any] = {"leaf": "value"}
    for _ in range(depth):
        payload = {"child": payload}
    return payload


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param({"node_id": ""}, id="empty-node-id"),
        pytest.param({}, id="missing-node-id"),
        pytest.param({"node_id": "canary\nforged"}, id="newline-in-node-id"),
        pytest.param({"node_id": "n1", "src_host": "10.0.0.5\r\nFAKE"}, id="crlf-in-host"),
        pytest.param({"node_id": "n" * 129}, id="oversized-node-id"),
        pytest.param({"node_id": "n1", "src_port": 70000}, id="port-out-of-range"),
        pytest.param({"node_id": "n1", "src_port": float("nan")}, id="nan-port"),
        pytest.param({"node_id": "n1", "logtype": "abc"}, id="non-numeric-logtype"),
        pytest.param({"node_id": "n1", "logdata": nested_logdata(20)}, id="deep-nesting"),
        pytest.param(
            {"node_id": "n1", "logdata": {f"k{index}": index for index in range(2500)}},
            id="too-many-logdata-nodes",
        ),
        pytest.param({"node_id": "n1", "logdata": {"x": float("inf")}}, id="infinite-number"),
        pytest.param({"node_id": "n1", "logdata": {"k" * 129: "v"}}, id="oversized-logdata-key"),
    ],
)
def test_hostile_payloads_are_rejected(payload: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        CanaryEvent.model_validate(payload)


def test_redacted_event_masks_captured_credentials(event_factory: Any) -> None:
    event = CanaryEvent.model_validate(event_factory())

    assert event.redacted().logdata["PASSWORD"] == "***"
    assert event.logdata["PASSWORD"] == "hunter2"


# --- Typed logdata accessors ------------------------------------------------


def test_ftp_login_accessor_reads_captured_credentials(event_factory: Any) -> None:
    data = FtpLoginData.from_event(CanaryEvent.model_validate(event_factory()))

    assert data.USERNAME == "admin"
    assert data.PASSWORD == "hunter2"
    assert data.redacted().PASSWORD == "***"


def test_http_login_accessor_keeps_extra_fields() -> None:
    data = HttpLoginData.from_logdata(
        {"USERNAME": "root", "PATH": "/admin", "USERAGENT": "curl/8", "EXTRA": "kept"}
    )

    assert data.PATH == "/admin"
    assert data.model_extra == {"EXTRA": "kept"}


def test_logdata_accessors_coerce_scalars_and_default_missing_fields() -> None:
    assert SshLoginData.from_logdata({"USERNAME": 5}).USERNAME == "5"
    assert SmbFileOpenData.from_logdata({}).FILENAME == ""
    assert UserData.from_logdata({"anything": "goes"}).model_extra == {"anything": "goes"}


# --- Incident records -------------------------------------------------------


def test_incident_record_coerces_legacy_string_fields() -> None:
    record = IncidentRecord.model_validate(
        {
            "key": "incident:ftplogin:10.0.0.5:1418997029.99",
            "node_id": "canary-1",
            "created": "1418997029.99",
            "events_count": "4",
            "logtype": "2000",
            "acknowledged": "False",
            "notified": "False",
            "updated": "True",
            "events_list": "1418997029.99,1418997030.76",
        }
    )

    assert record.created == pytest.approx(1418997029.99)
    assert record.events_count == 4
    assert record.logtype == 2000
    assert record.acknowledged is False
    assert record.updated is True


def test_incident_record_requires_creation_timestamp() -> None:
    with pytest.raises(ValidationError):
        IncidentRecord.model_validate({"node_id": "canary-1"})


def test_a_naive_datetime_is_read_as_utc() -> None:
    """A canary that builds a datetime object sends it without a zone.

    Treating it as local time would shift every incident by the host's offset.
    """
    event = CanaryEvent.model_validate({"node_id": "n1", "local_time": datetime(2026, 10, 24, 10)})

    assert event.local_time == datetime(2026, 10, 24, 10, tzinfo=UTC)


def test_a_single_digit_date_falls_back_to_the_explicit_formats() -> None:
    """`fromisoformat` needs zero-padded fields; the OpenCanary app does not always pad."""
    event = CanaryEvent.model_validate({"node_id": "n1", "local_time": "2026-1-4 10:00:00"})

    assert event.local_time == datetime(2026, 1, 4, 10, 0, tzinfo=UTC)


def test_a_non_text_non_numeric_timestamp_is_ignored() -> None:
    """`local_time` can arrive as a list from a broken encoder; it must not raise."""
    event = CanaryEvent.model_validate({"node_id": "n1", "local_time": [2026, 10, 24]})

    assert event.local_time is None


def test_an_explicit_none_reported_destination_is_accepted() -> None:
    """The field is optional, and senders do write an explicit null."""
    event = CanaryEvent.model_validate({"node_id": "n1", "reported_dst_host": None})

    assert event.reported_dst_host is None


def test_logdata_of_an_unsupported_type_is_rejected() -> None:
    """Only an object, a scalar or a sequence is storable; anything else is a bug."""
    with pytest.raises(ValidationError):
        CanaryEvent.model_validate({"node_id": "n1", "logdata": datetime(2026, 10, 24)})


def test_logdata_scalars_are_stringified_including_none_and_bools() -> None:
    """Typed accessors expect strings; `None` and `True` must not leak as non-strings."""
    assert SshLoginData.from_logdata({"USERNAME": None}).USERNAME == ""
    assert SshLoginData.from_logdata({"USERNAME": True}).USERNAME == "True"
