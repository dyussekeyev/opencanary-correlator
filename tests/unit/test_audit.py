"""Tests for the JSON audit trail and the bounded Redis log handler."""

from __future__ import annotations

import io
import json
import logging

import pytest
from pydantic import ValidationError

from opencanary_correlator.audit import AuditEvent, AuditLogger, RedisLogHandler

MANDATORY_FIELDS = {"timestamp", "component", "action", "status", "details"}


class CollectingSink:
    """Minimal async log sink recording what it receives."""

    def __init__(self) -> None:
        self.lines: list[str] = []
        self.max_entries: list[int] = []
        self.fail = False

    async def push_log(self, line: str, *, max_entries: int) -> None:
        if self.fail:
            raise RuntimeError("sink unavailable")
        self.lines.append(line)
        self.max_entries.append(max_entries)


class BrokenStream(io.StringIO):
    """Stream that fails on write, as a closed pipe would."""

    def write(self, _value: str) -> int:
        raise OSError("stream closed")


def make_logger(name: str, handler: logging.Handler) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.handlers = [handler]
    logger.setLevel(logging.INFO)
    logger.propagate = False
    return logger


# --- Audit events -----------------------------------------------------------


def test_audit_event_requires_mandatory_fields() -> None:
    with pytest.raises(ValidationError):
        AuditEvent.model_validate({"component": "correlator", "action": "startup"})


@pytest.mark.parametrize("component", ["Correlator", "cor relator", "", "-leading"])
def test_audit_event_rejects_malformed_component(component: str) -> None:
    with pytest.raises(ValidationError):
        AuditEvent(component=component, action="startup", status="info")


def test_emit_writes_one_json_line_with_required_fields() -> None:
    stream = io.StringIO()
    logger = AuditLogger("correlator", stream=stream)

    logger.emit(
        "startup",
        "info",
        {"port": 1514, "PASSWORD": "hunter2", "note": "line one\nline two"},
    )

    lines = stream.getvalue().splitlines()
    assert len(lines) == 1
    payload = json.loads(lines[0])
    assert set(payload) == MANDATORY_FIELDS
    assert payload["component"] == "correlator"
    assert payload["action"] == "startup"
    assert payload["status"] == "info"
    assert payload["details"]["port"] == 1514
    assert payload["details"]["PASSWORD"] == "***"
    assert "\n" not in payload["details"]["note"]


def test_emit_returns_the_written_record() -> None:
    logger = AuditLogger("tcp_receiver", stream=io.StringIO())

    record = logger.emit("event_rejected", "error", {"reason": "line_too_large"})

    assert record.component == "tcp_receiver"
    assert record.action == "event_rejected"
    assert record.status == "error"


def test_emit_falls_back_to_stderr_when_stream_is_broken(capsys) -> None:
    logger = AuditLogger("correlator", stream=BrokenStream())

    logger.emit("shutdown", "info", {})

    captured = capsys.readouterr()
    assert json.loads(captured.err.strip())["action"] == "shutdown"


def test_emit_rejects_invalid_action_name() -> None:
    logger = AuditLogger("correlator", stream=io.StringIO())

    with pytest.raises(ValidationError):
        logger.emit("Not An Action", "info")


# --- Bounded Redis log handler ---------------------------------------------


async def test_handler_flushes_records_to_sink() -> None:
    sink = CollectingSink()
    handler = RedisLogHandler(sink, queue_size=10, max_entries=50)
    log = make_logger("tests.audit.flush", handler)

    await handler.start()
    log.info("first")
    log.info("second")
    await handler.stop()

    assert sink.lines == ["first", "second"]
    assert sink.max_entries == [50, 50]
    assert handler.pending == 0


async def test_handler_counts_overflow_instead_of_growing() -> None:
    sink = CollectingSink()
    handler = RedisLogHandler(sink, queue_size=1)
    record = logging.LogRecord("x", logging.INFO, __file__, 1, "message", None, None)

    handler.emit(record)
    handler.emit(record)

    assert handler.pending == 1
    assert handler.dropped == 1


async def test_handler_survives_sink_failure() -> None:
    sink = CollectingSink()
    sink.fail = True
    handler = RedisLogHandler(sink, queue_size=10)
    log = make_logger("tests.audit.failure", handler)

    await handler.start()
    log.error("cannot be stored")
    await handler.stop()

    assert handler.dropped == 1
    assert sink.lines == []


async def test_handler_emit_never_raises_on_unformattable_record() -> None:
    handler = RedisLogHandler(CollectingSink(), queue_size=1)
    handler.setFormatter(logging.Formatter("%(missing)s"))

    record = logging.LogRecord("x", logging.INFO, __file__, 1, "message", None, None)
    handler.emit(record)  # must not raise

    assert handler.pending == 0 or handler.dropped == 1
