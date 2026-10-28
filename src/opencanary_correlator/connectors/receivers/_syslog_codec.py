"""The syslog codec: bytes in, a canary event out.

Nothing here touches a socket, a task or an audit sink, so the parsing rules can
be tested on their own and the receivers stay thin transports.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from opencanary_correlator.connectors.receivers._pipeline import schema_error_details
from opencanary_correlator.constants import LogType
from opencanary_correlator.schemas import CanaryEvent

_PRI_RE = re.compile(r"^<(?P<pri>\d{1,3})>")
_RFC5424_RE = re.compile(
    r"^(?P<version>\d)\s+(?P<timestamp>\S+)\s+(?P<hostname>\S+)\s+(?P<app_name>\S+)\s+"
    r"(?P<procid>\S+)\s+(?P<msgid>\S+)\s*(?P<rest>.*)$",
    re.DOTALL,
)
_RFC3164_RE = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+"
    r"(?P<rest>.*)$",
    re.DOTALL,
)
_TAG_RE = re.compile(r"^(?P<tag>[A-Za-z0-9_.\-/]+)(?:\[\d+\])?:\s?")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_MAX_NODE_ID_LENGTH = 128


@dataclass(frozen=True, slots=True)
class SyslogMessage:
    """Parsed syslog envelope."""

    pri: int | None
    facility: int | None
    severity: int | None
    version: int | None
    timestamp: str | None
    hostname: str | None
    app_name: str | None
    message: str


def _clean_node_id(candidate: str | None) -> str:
    if not candidate:
        return "syslog"
    cleaned = _CONTROL_RE.sub("_", candidate)[:_MAX_NODE_ID_LENGTH]
    return cleaned or "syslog"


def _skip_structured_data(text: str) -> str:
    """Drop RFC 5424 structured-data blocks that precede the message."""
    while text.startswith("["):
        depth = 0
        in_quotes = False
        escaped = False
        consumed = 0
        for index, character in enumerate(text):
            if escaped:
                escaped = False
                continue
            if character == "\\":
                escaped = True
                continue
            if character == '"':
                in_quotes = not in_quotes
                continue
            if in_quotes:
                continue
            if character == "[":
                depth += 1
            elif character == "]":
                depth -= 1
                if depth == 0:
                    consumed = index + 1
                    break
        if consumed == 0:
            return ""
        text = text[consumed:].lstrip()
    return text


def parse_syslog(raw: bytes) -> SyslogMessage:
    """Parse a syslog envelope, raising :class:`ValueError` on a broken PRI."""
    text = raw.decode("utf-8", errors="replace").rstrip("\x00").strip("\r\n")
    if not text:
        raise ValueError("empty syslog message")

    pri: int | None = None
    match = _PRI_RE.match(text)
    if match is not None:
        pri = int(match.group("pri"))
        if pri > 191:
            raise ValueError(f"PRI out of range: {pri}")
        text = text[match.end() :]
    elif text.startswith("<"):
        raise ValueError("malformed PRI")

    facility = pri // 8 if pri is not None else None
    severity = pri % 8 if pri is not None else None

    version: int | None = None
    timestamp: str | None = None
    hostname: str | None = None
    app_name: str | None = None
    body = text

    rfc5424 = _RFC5424_RE.match(text)
    if rfc5424 is not None:
        version = int(rfc5424.group("version"))
        raw_timestamp = rfc5424.group("timestamp")
        timestamp = None if raw_timestamp == "-" else raw_timestamp
        hostname = rfc5424.group("hostname")
        app_name = rfc5424.group("app_name")
        remainder = rfc5424.group("rest").lstrip("\ufeff ")
        # RFC 5424 uses a lone "-" for absent structured data.
        if remainder == "-" or remainder.startswith("- "):
            remainder = remainder[1:].lstrip()
        body = _skip_structured_data(remainder)
    else:
        rfc3164 = _RFC3164_RE.match(text)
        if rfc3164 is not None:
            timestamp = rfc3164.group("timestamp")
            hostname = rfc3164.group("hostname")
            remainder = rfc3164.group("rest")
            tag = _TAG_RE.match(remainder)
            if tag is not None:
                app_name = tag.group("tag")
                remainder = remainder[tag.end() :]
            body = remainder.lstrip("\ufeff ")

    return SyslogMessage(
        pri=pri,
        facility=facility,
        severity=severity,
        version=version,
        timestamp=timestamp,
        hostname=hostname,
        app_name=app_name,
        message=body.strip(),
    )


def build_event(message: SyslogMessage, peer_ip: str) -> CanaryEvent:
    """Turn a parsed syslog message into a canary event.

    Raises :class:`pydantic.ValidationError` when a JSON body does not satisfy
    the event schema.
    """
    body = message.message.strip()
    node_id = _clean_node_id(message.hostname)

    # A JSON body may be the whole message or follow an unrecognised header
    # (``host app: {...}``). Only an explicitly JSON body is allowed to raise;
    # an embedded candidate that does not parse falls back to a text event.
    json_start = body.find("{")
    payload: Any = None
    if json_start == 0:
        payload = json.loads(body)
    elif json_start > 0:
        try:
            payload = json.loads(body[json_start:])
        except json.JSONDecodeError:
            payload = None
    if isinstance(payload, dict):
        payload.setdefault("node_id", node_id)
        payload.setdefault("src_host", peer_ip)
        payload.setdefault("logtype", int(LogType.LOG_BASE_MSG))
        payload.setdefault("logdata", {})
        if message.timestamp is not None:
            payload.setdefault("local_time", message.timestamp)
        return CanaryEvent.model_validate(payload)

    logdata: dict[str, Any] = {"message": body}
    if message.app_name:
        logdata["app_name"] = message.app_name
    if message.pri is not None:
        logdata["pri"] = message.pri
        logdata["facility"] = message.facility
        logdata["severity"] = message.severity

    payload = {
        "node_id": node_id,
        "src_host": peer_ip,
        "logtype": int(LogType.LOG_BASE_MSG),
        "logdata": logdata,
    }
    if message.timestamp is not None:
        payload["local_time"] = message.timestamp
    return CanaryEvent.model_validate(payload)


def parse_syslog_frame(
    payload: bytes,
    peer_ip: str,
    audit_rejection: Callable[..., None],
) -> CanaryEvent | None:
    """Parse one syslog frame into an event, auditing and skipping any rejection.

    Shared by the TCP and UDP receivers so both reject the same inputs the same way.
    """
    try:
        message = parse_syslog(payload)
    except ValueError as exc:
        audit_rejection("malformed_syslog", peer_ip, error=str(exc))
        return None
    try:
        return build_event(message, peer_ip)
    except json.JSONDecodeError:
        audit_rejection("malformed_json", peer_ip)
        return None
    except ValidationError as exc:
        audit_rejection("schema_validation", peer_ip, **schema_error_details(exc))
        return None


__all__ = [
    "SyslogMessage",
    "build_event",
    "parse_syslog",
    "parse_syslog_frame",
]
