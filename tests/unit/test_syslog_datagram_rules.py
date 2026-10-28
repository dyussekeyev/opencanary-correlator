"""Unit tests for the UDP syslog receiver's per-datagram rules.

The receiver is exercised without a socket: ``datagram_received`` is the whole
decision surface (allowlist, size budget, splitting, parsing) and the pipeline
records what happened, so the rules can be asserted directly instead of through
a real send that only indirectly proves the outcome.
"""

from __future__ import annotations

import json
from typing import Any

from opencanary_correlator.connectors.receivers._allowlist import parse_allowed_networks
from opencanary_correlator.connectors.receivers.syslog import SyslogUDPReceiver


class _NullSink:
    """Sink that accepts events and remembers nothing."""

    async def handle_event(self, event: Any) -> None:
        """Drop the event."""


def make_receiver(audit: Any, **overrides: Any) -> SyslogUDPReceiver:
    """Build a receiver that is never started, so no port is bound."""
    params: dict[str, Any] = {
        "sink": _NullSink(),
        "audit": audit,
        "host": "127.0.0.1",
        "port": 0,
    }
    params.update(overrides)
    return SyslogUDPReceiver(**params)


def audit_records(audit_stream: Any) -> list[dict[str, Any]]:
    """Parse the captured audit stream into records."""
    return [json.loads(line) for line in audit_stream.getvalue().splitlines() if line.strip()]


def sample_payload(**overrides: Any) -> bytes:
    """A minimal valid canary event as a syslog body."""
    payload: dict[str, Any] = {
        "node_id": "canary-1",
        "src_host": "10.0.0.5",
        "dst_port": 21,
        "logtype": 2000,
        "logdata": {"USERNAME": "admin"},
    }
    payload.update(overrides)
    return json.dumps(payload).encode()


def test_a_peer_outside_the_allowlist_never_reaches_the_queue(
    audit: Any, audit_stream: Any
) -> None:
    """The allowlist is checked before parsing, so a forbidden peer cannot queue work."""
    receiver = make_receiver(audit, allowed_networks=parse_allowed_networks(["10.0.0.0/8"]))

    receiver.datagram_received(b"<134>canary-1 app: " + sample_payload(), "203.0.113.5")

    assert receiver.pending == 0
    assert receiver.stats.rejected == 1
    rejected = [
        record for record in audit_records(audit_stream) if record["action"] == "event_rejected"
    ]
    assert rejected[0]["details"]["reason"] == "peer_not_allowed"
    assert rejected[0]["details"]["peer"] == "203.0.113.5"


def test_an_allowed_peer_is_accepted(audit: Any) -> None:
    """The same datagram passes once the peer is inside the allowlist."""
    receiver = make_receiver(audit, allowed_networks=parse_allowed_networks(["10.0.0.0/8"]))

    receiver.datagram_received(b"<134>canary-1 app: " + sample_payload(), "10.1.2.3")

    assert receiver.pending == 1
    assert receiver.stats.rejected == 0


def test_one_datagram_can_carry_several_events(audit: Any) -> None:
    """A batching sender packs several lines into one datagram; blank lines are skipped.

    Every line becomes its own event: treating the datagram as a single payload
    would parse only the first one and silently drop the rest.
    """
    receiver = make_receiver(audit)
    datagram = (
        b"<134>canary-1 app: "
        + sample_payload(dst_port=21)
        + b"\n\n<134>canary-1 app: "
        + sample_payload(dst_port=22)
        + b"\n"
    )

    receiver.datagram_received(datagram, "10.0.0.9")

    assert receiver.pending == 2
    assert receiver.stats.rejected == 0


def test_a_broken_line_does_not_discard_the_rest_of_the_datagram(
    audit: Any, audit_stream: Any
) -> None:
    """One malformed frame costs one event, not the whole datagram."""
    receiver = make_receiver(audit)
    datagram = b"<abc>broken\n<134>canary-1 app: " + sample_payload()

    receiver.datagram_received(datagram, "10.0.0.9")

    assert receiver.pending == 1
    assert receiver.stats.rejected == 1
    actions = [
        (record["action"], record["details"].get("reason"))
        for record in audit_records(audit_stream)
    ]
    assert ("event_rejected", "malformed_syslog") in actions


def test_a_datagram_error_is_audited_with_its_exception_type(audit: Any, audit_stream: Any) -> None:
    """Transport-level failures are recorded as `datagram_error`, never raised.

    The protocol callback has no caller to propagate to; an unrecorded error
    here would look like a silent gap in the event stream.
    """
    receiver = make_receiver(audit)

    receiver.audit_error(RuntimeError("socket went away"))

    (record,) = audit_records(audit_stream)
    assert record["action"] == "datagram_error"
    assert record["status"] == "error"
    assert record["details"] == {"receiver": "syslog_udp", "error_type": "RuntimeError"}


# --- frame-level rejection reasons -------------------------------------------


def frame_rejections(payload: bytes) -> list[dict[str, Any]]:
    """Run one frame through the codec and return the audit records it produced."""
    from opencanary_correlator.connectors.receivers._syslog_codec import parse_syslog_frame

    records: list[dict[str, Any]] = []

    def audit(reason: str, peer_ip: str, **details: Any) -> None:
        records.append({"reason": reason, "peer": peer_ip, **details})

    assert parse_syslog_frame(payload, "10.0.0.9", audit) is None
    return records


def test_a_body_that_is_json_but_does_not_decode_is_reported_as_malformed_json() -> None:
    """``{"logtype": `` is a truncated event, not a text message.

    The codec refuses it; the audit reason is what tells an operator that the
    sender is broken rather than the schema being too strict.
    """
    records = frame_rejections(b'<134>{"logtype": ')

    assert [record["reason"] for record in records] == ["malformed_json"]


def test_a_schema_failure_names_the_offending_field() -> None:
    """An operator needs the field, not just "invalid event"."""
    records = frame_rejections(b'<134>{"node_id": "", "logtype": 2000}')

    (record,) = records
    assert record["reason"] == "schema_validation"
    assert record["first_error"] == "node_id"
    assert record["error_count"] >= 1


async def test_stopping_a_receiver_that_was_never_started_is_safe(
    audit: Any, audit_stream: Any
) -> None:
    """Shutdown must not depend on start having succeeded.

    A receiver whose socket failed to bind is still stopped by the supervisor;
    raising here would mask the original error.
    """
    receiver = make_receiver(audit)

    await receiver.stop()

    actions = [record["action"] for record in audit_records(audit_stream)]
    assert actions == ["receiver_stopped"]
