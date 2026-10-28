"""Unit tests for RFC 3164/5424 parsing and syslog event construction."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from opencanary_correlator.connectors.receivers.syslog import build_event, parse_syslog
from opencanary_correlator.constants import LogType


def test_rfc5424_envelope_is_parsed() -> None:
    message = parse_syslog(
        b"<34>1 2026-10-24T10:00:00Z canary-1 opencanary 123 ID47 - login attempt"
    )

    assert message.pri == 34
    assert message.facility == 4
    assert message.severity == 2
    assert message.version == 1
    assert message.hostname == "canary-1"
    assert message.app_name == "opencanary"
    assert message.timestamp == "2026-10-24T10:00:00Z"
    assert message.message == "login attempt"


def test_rfc5424_structured_data_is_skipped() -> None:
    message = parse_syslog(
        b"<34>1 2026-10-24T10:00:00Z canary-1 opencanary - ID47 "
        b'[exampleSDID@32473 iut="3" eventSource="x"] {"logtype": 2000}'
    )

    assert message.message == '{"logtype": 2000}'


def test_rfc3164_tag_is_stripped() -> None:
    message = parse_syslog(b"<134>Oct 24 10:00:00 canary-1 opencanary[42]: login attempt")

    assert message.pri == 134
    assert message.hostname == "canary-1"
    assert message.app_name == "opencanary"
    assert message.message == "login attempt"
    assert message.version is None


def test_trailing_nul_from_python_syslog_handler_is_removed() -> None:
    message = parse_syslog(b"<134>Oct 24 10:00:00 canary-1 opencanary: hello\x00")

    assert message.message == "hello"


def test_message_without_pri_is_still_accepted() -> None:
    message = parse_syslog(b"just some text")

    assert message.pri is None
    assert message.facility is None
    assert message.message == "just some text"


@pytest.mark.parametrize("raw", [b"<abc>broken", b"<999>out-of-range", b""])
def test_malformed_envelopes_raise(raw: bytes) -> None:
    with pytest.raises(ValueError):
        parse_syslog(raw)


def test_json_body_becomes_a_canary_event() -> None:
    payload = {
        "node_id": "canary-7",
        "src_host": "10.0.0.5",
        "dst_port": 21,
        "logtype": 2000,
        "logdata": {"USERNAME": "admin"},
    }
    message = parse_syslog(b"<134>canary-7 opencanary: " + json.dumps(payload).encode())

    event = build_event(message, "10.0.0.9")

    assert event.node_id == "canary-7"
    assert event.src_host == "10.0.0.5"
    assert event.logtype is LogType.LOG_FTP_LOGIN_ATTEMPT


def test_json_body_inherits_hostname_and_peer_when_incomplete() -> None:
    message = parse_syslog(b'<134>Oct 24 10:00:00 canary-2 opencanary: {"logdata": {"a": 1}}')

    event = build_event(message, "10.0.0.9")

    assert event.node_id == "canary-2"
    assert event.src_host == "10.0.0.9"
    assert event.logtype is LogType.LOG_BASE_MSG


def test_plain_text_body_becomes_synthetic_event() -> None:
    message = parse_syslog(b"<134>Oct 24 10:00:00 canary-3 sshd: failed password")

    event = build_event(message, "10.0.0.9")

    assert event.logtype is LogType.LOG_BASE_MSG
    assert event.logdata["message"] == "failed password"
    assert event.logdata["app_name"] == "sshd"
    assert event.logdata["severity"] == 6
    assert event.logdata["facility"] == 16


def test_broken_embedded_json_falls_back_to_text_event() -> None:
    message = parse_syslog(b'<134>canary-4 app: {"logtype": ')

    event = build_event(message, "10.0.0.9")

    assert event.logtype is LogType.LOG_BASE_MSG
    assert '{"logtype"' in event.logdata["message"]


def test_broken_explicit_json_body_raises_json_error() -> None:
    message = parse_syslog(b'<134>{"logtype": ')

    with pytest.raises(json.JSONDecodeError):
        build_event(message, "10.0.0.9")


def test_invalid_event_body_raises_validation_error() -> None:
    message = parse_syslog(b'<134>canary-5 app: {"node_id": "", "logtype": 2000}')

    with pytest.raises(ValidationError):
        build_event(message, "10.0.0.9")


# --- structured data ---------------------------------------------------------


def test_brackets_inside_a_quoted_value_do_not_end_the_block_early() -> None:
    """A ``]`` inside a quoted parameter is data, not the end of the block.

    The block is skipped with a quote-aware scan; a naive ``text.split("]")``
    would hand the rest of the block to the event parser as the body.
    """
    message = parse_syslog(
        b"<34>1 2026-10-24T10:00:00Z canary-1 opencanary - ID47 "
        b'[exampleSDID@32473 note="closed ] bracket"] login attempt'
    )

    assert message.message == "login attempt"


def test_escaped_quotes_do_not_end_the_block_early() -> None:
    message = parse_syslog(
        b"<34>1 2026-10-24T10:00:00Z canary-1 opencanary - ID47 "
        b'[exampleSDID@32473 note="say \\"hi\\" ]"] login attempt'
    )

    assert message.message == "login attempt"


def test_several_structured_blocks_are_skipped() -> None:
    message = parse_syslog(
        b"<34>1 2026-10-24T10:00:00Z canary-1 opencanary - ID47 "
        b'[a@1 x="1"][b@2 y="2"] login attempt'
    )

    assert message.message == "login attempt"


def test_an_unterminated_structured_block_leaves_no_body() -> None:
    """Half a block must not be reinterpreted as the message."""
    message = parse_syslog(b'<34>1 2026-10-24T10:00:00Z canary-1 opencanary - ID47 [a@1 note="x"')

    assert message.message == ""


# --- node id hygiene ---------------------------------------------------------


def test_hostname_control_characters_are_replaced_in_the_node_id() -> None:
    """The node id becomes a storage key, so a control byte must not survive.

    A hostile honeypot can put ``\x00`` or a newline in the hostname field; the
    id is used in Redis key composition and in audit records.
    """
    message = parse_syslog(b"<134>Oct 24 10:00:00 bad\x00host app: hello")

    event = build_event(message, "10.0.0.9")

    assert event.node_id == "bad_host"


def test_an_over_long_hostname_is_clipped_to_the_key_limit() -> None:
    message = parse_syslog(b"<134>Oct 24 10:00:00 " + b"h" * 200 + b" app: hello")

    event = build_event(message, "10.0.0.9")

    assert len(event.node_id) == 128


def test_a_message_without_a_hostname_falls_back_to_the_default_node_id() -> None:
    event = build_event(parse_syslog(b"<134>just some text"), "10.0.0.9")

    assert event.node_id == "syslog"
