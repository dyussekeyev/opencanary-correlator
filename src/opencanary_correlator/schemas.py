"""Pydantic v2 models for OpenCanary events and correlated incidents.

Compatibility rules encoded here (see ``docs/EXECPLAN-refactor.md``):

* unknown fields are preserved (``extra="allow"``), never rejected;
* ``src_host`` may be an empty string, a hostname or an IPv6 address;
* ports may be ``-1`` (the canary default) up to 65535;
* unknown ``logtype`` integers are accepted;
* an unparsable timestamp is not fatal - callers fall back to the receipt time
  through :meth:`CanaryEvent.resolved_time`;
* ``logdata`` is normally an object; a scalar is preserved under ``"raw"``.
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from typing import Annotated, Any, Final, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationInfo,
    field_validator,
)

from opencanary_correlator.constants import DEFAULT_LOGTYPE, LogType
from opencanary_correlator.redaction import redact_mapping

MAX_LOGDATA_DEPTH: Final[int] = 5
MAX_LOGDATA_NODES: Final[int] = 2000
MAX_LOGDATA_KEY_LENGTH: Final[int] = 128

HostString = Annotated[str, StringConstraints(max_length=255)]
NodeIdentifier = Annotated[str, StringConstraints(min_length=1, max_length=128)]
PortNumber = Annotated[int, Field(ge=-1, le=65535)]

_TIMESTAMP_FORMATS: Final[tuple[str, ...]] = (
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
)


def _reject_control_characters(value: str, field_name: str) -> str:
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError(f"{field_name} must not contain control characters")
    return value


def _parse_timestamp(value: Any) -> datetime | None:
    """Parse every timestamp shape a canary may send, returning None if unknown."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        if not math.isfinite(value) or value < 0:
            return None
        return datetime.fromtimestamp(value, tz=UTC)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        if text.endswith("Z"):
            text = f"{text[:-1]}+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            parsed = None
        if parsed is None:
            for fmt in _TIMESTAMP_FORMATS:
                try:
                    parsed = datetime.strptime(text, fmt)
                except ValueError:
                    continue
                break
        if parsed is None:
            return None
        return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)
    return None


def _walk_logdata(value: Any, depth: int = 0) -> Iterable[tuple[int, Any, Any]]:
    """Yield ``(depth, key, item)`` triples without recursing unboundedly."""
    stack: list[tuple[int, Any, Any]] = [(depth, None, value)]
    while stack:
        current_depth, key, item = stack.pop()
        yield current_depth, key, item
        if isinstance(item, Mapping):
            for child_key, child_value in item.items():
                stack.append((current_depth + 1, child_key, child_value))
        elif isinstance(item, (list, tuple)):
            for child_value in item:
                stack.append((current_depth + 1, key, child_value))


def _validate_logdata_bounds(value: Mapping[str, Any]) -> None:
    nodes = 0
    for depth, key, item in _walk_logdata(value):
        nodes += 1
        if depth > MAX_LOGDATA_DEPTH:
            raise ValueError(f"logdata nesting exceeds {MAX_LOGDATA_DEPTH} levels")
        if nodes > MAX_LOGDATA_NODES:
            raise ValueError(f"logdata exceeds {MAX_LOGDATA_NODES} nodes")
        if key is not None and len(str(key)) > MAX_LOGDATA_KEY_LENGTH:
            raise ValueError(f"logdata key exceeds {MAX_LOGDATA_KEY_LENGTH} characters")
        if isinstance(item, float) and not math.isfinite(item):
            raise ValueError("logdata must not contain non-finite numbers")


class CanaryEvent(BaseModel):
    """A single event emitted by `opencanaryd` over its JSON socket handler."""

    model_config = ConfigDict(extra="allow", str_max_length=4096)

    src_host: HostString = ""
    src_port: PortNumber = -1
    dst_host: HostString = ""
    dst_port: PortNumber = -1
    logtype: Annotated[LogType | int, Field(union_mode="left_to_right")] = DEFAULT_LOGTYPE
    node_id: NodeIdentifier
    local_time: datetime | None = None
    utc_time: datetime | None = None
    local_time_adjusted: datetime | None = None
    logdata: dict[str, Any] = Field(default_factory=dict)
    reported_dst_host: HostString | None = None

    @field_validator("src_host", "dst_host", "reported_dst_host")
    @classmethod
    def _clean_hosts(cls, value: str | None, info: ValidationInfo) -> str | None:
        if value is None:
            return None
        return _reject_control_characters(value, info.field_name or "host")

    @field_validator("node_id")
    @classmethod
    def _clean_node_id(cls, value: str) -> str:
        return _reject_control_characters(value, "node_id")

    @field_validator("local_time", "utc_time", "local_time_adjusted", mode="before")
    @classmethod
    def _coerce_timestamps(cls, value: Any) -> datetime | None:
        return _parse_timestamp(value)

    @field_validator("logdata", mode="before")
    @classmethod
    def _normalise_logdata(cls, value: Any) -> dict[str, Any]:
        if value is None:
            return {}
        if isinstance(value, Mapping):
            return {str(key): item for key, item in value.items()}
        if isinstance(value, (str, int, float, bool)):
            return {"raw": value}
        if isinstance(value, (list, tuple, set, frozenset)):
            return {"raw": list(value)}
        raise ValueError("logdata must be an object, scalar or list")

    @field_validator("logdata")
    @classmethod
    def _bound_logdata(cls, value: dict[str, Any]) -> dict[str, Any]:
        _validate_logdata_bounds(value)
        return value

    @property
    def is_known_logtype(self) -> bool:
        """True when the event's log type is part of the :class:`LogType` registry."""
        return isinstance(self.logtype, LogType)

    def resolved_time(self, received_at: datetime) -> datetime:
        """Return the event timestamp, falling back to the receipt time."""
        timestamp = self.local_time or self.utc_time
        if timestamp is None:
            return received_at
        return timestamp if timestamp.tzinfo is not None else timestamp.replace(tzinfo=UTC)

    def redacted(self) -> CanaryEvent:
        """Return a copy whose `logdata` is safe to write to logs."""
        return self.model_copy(update={"logdata": redact_mapping(self.logdata)})


class LogDataModel(BaseModel):
    """Base class for typed access to a canary's `logdata` object."""

    model_config = ConfigDict(extra="allow", str_max_length=4096)

    @field_validator("*", mode="before")
    @classmethod
    def _stringify_scalars(cls, value: Any) -> Any:
        if value is None:
            return ""
        if isinstance(value, bool):
            return str(value)
        if isinstance(value, (int, float)):
            return str(value)
        return value

    @classmethod
    def from_event(cls, event: CanaryEvent) -> Self:
        """Build the typed view from an already validated event."""
        return cls.model_validate(event.logdata)

    @classmethod
    def from_logdata(cls, logdata: Mapping[str, Any]) -> Self:
        """Build the typed view directly from a raw `logdata` mapping."""
        return cls.model_validate(dict(logdata))

    def redacted(self) -> Self:
        """Return a copy with credentials masked."""
        return type(self).model_validate(redact_mapping(self.model_dump()))


class FtpLoginData(LogDataModel):
    """`LOG_FTP_LOGIN_ATTEMPT` payload."""

    USERNAME: str = ""
    PASSWORD: str = ""


class HttpLoginData(LogDataModel):
    """`LOG_HTTP_POST_LOGIN_ATTEMPT` payload."""

    USERNAME: str = ""
    PASSWORD: str = ""
    HOSTNAME: str = ""
    PATH: str = ""
    USERAGENT: str = ""


class SshLoginData(LogDataModel):
    """`LOG_SSH_LOGIN_ATTEMPT` payload."""

    USERNAME: str = ""
    PASSWORD: str = ""


class SmbFileOpenData(LogDataModel):
    """`LOG_SMB_FILE_OPEN` payload."""

    FILENAME: str = ""
    USER: str = ""


class UserData(LogDataModel):
    """Payload of user-defined log types (`LOG_USER_*`); arbitrary keys."""


class IncidentRecord(BaseModel):
    """Incident hash as stored in Redis, with legacy string coercions.

    The Python 2 implementation wrote every value as a string (`"True"`,
    `"False"`, `"4"`), so those shapes must still validate.
    """

    model_config = ConfigDict(extra="allow")

    key: str = ""
    node_id: str
    src_host: str = ""
    src_port: int = -1
    dst_host: str = ""
    dst_port: int = -1
    logtype: int = int(DEFAULT_LOGTYPE)
    created: float
    events_list: str = ""
    events_count: int = 0
    acknowledged: bool = False
    notified: bool = False
    updated: bool = False
    description: str = ""
    logdata: str | None = None


__all__ = [
    "MAX_LOGDATA_DEPTH",
    "MAX_LOGDATA_KEY_LENGTH",
    "MAX_LOGDATA_NODES",
    "CanaryEvent",
    "FtpLoginData",
    "HttpLoginData",
    "IncidentRecord",
    "LogDataModel",
    "SmbFileOpenData",
    "SshLoginData",
    "UserData",
]
