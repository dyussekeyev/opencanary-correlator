"""Strict value objects exchanged between the MISP builder, queue and client."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


def utc(value: datetime) -> datetime:
    """Return an aware UTC datetime; a naive value is interpreted as UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def iso(value: datetime) -> str:
    """Canonical MISP timestamp: UTC, second precision, trailing `Z`."""
    return utc(value).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class MispObservation(BaseModel):
    """One source address aggregated over one publication window."""

    model_config = ConfigDict(extra="ignore", frozen=True)

    ip: str
    first_seen: datetime
    last_seen: datetime
    count: int = Field(ge=1)
    services: dict[str, int] = Field(default_factory=dict)
    ports: dict[int, int] = Field(default_factory=dict)
    #: Optional geo context from the local MMDB. It is copied only when the
    #: enrichment actually ran; no address is sent to a third party for this.
    country_code: str = ""
    country: str = ""
    asn: int | None = None
    as_org: str = ""

    @field_validator("first_seen", "last_seen")
    @classmethod
    def _aware_utc(cls, value: datetime) -> datetime:
        return utc(value)

    @field_validator("services")
    @classmethod
    def _clean_services(cls, value: dict[str, int]) -> dict[str, int]:
        cleaned: dict[str, int] = {}
        for name, count in value.items():
            key = name.strip()
            if not key or count < 1:
                continue
            cleaned[key] = cleaned.get(key, 0) + count
        return cleaned

    @field_validator("ports")
    @classmethod
    def _clean_ports(cls, value: dict[int, int]) -> dict[int, int]:
        cleaned: dict[int, int] = {}
        for port, count in value.items():
            if not 0 <= int(port) <= 65535 or count < 1:
                continue
            cleaned[int(port)] = cleaned.get(int(port), 0) + count
        return cleaned

    def merge(self, other: MispObservation) -> MispObservation:
        """Combine two observations for the same address.

        JSON object keys are strings after a Redis round trip; pydantic has
        already coerced the port keys back to integers by the time this runs.
        """
        if other.ip != self.ip:
            raise ValueError("only observations for the same address can be merged")
        services = dict(self.services)
        for name, count in other.services.items():
            services[name] = services.get(name, 0) + count
        ports = dict(self.ports)
        for port, count in other.ports.items():
            ports[port] = ports.get(port, 0) + count
        return MispObservation(
            ip=self.ip,
            first_seen=min(self.first_seen, other.first_seen),
            last_seen=max(self.last_seen, other.last_seen),
            count=self.count + other.count,
            services=services,
            ports=ports,
            country_code=self.country_code or other.country_code,
            country=self.country or other.country,
            asn=self.asn or other.asn,
            as_org=self.as_org or other.as_org,
        )


class MispWindow(BaseModel):
    """All eligible observations for one UTC aggregation window."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    start: datetime
    end: datetime
    observations: tuple[MispObservation, ...] = ()

    @field_validator("start", "end")
    @classmethod
    def _aware_utc(cls, value: datetime) -> datetime:
        return utc(value)

    @field_validator("observations")
    @classmethod
    def _unique_addresses(cls, value: tuple[MispObservation, ...]) -> tuple[MispObservation, ...]:
        merged: dict[str, MispObservation] = {}
        for observation in value:
            previous = merged.get(observation.ip)
            merged[observation.ip] = previous.merge(observation) if previous else observation
        return tuple(merged[key] for key in sorted(merged))

    @property
    def total_events(self) -> int:
        """Sum of event counts across all addresses."""
        return sum(item.count for item in self.observations)


class MispAttribute(BaseModel):
    """A MISP `ip-src` attribute with no raw honeypot material."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    uuid: UUID
    type: str = "ip-src"
    category: str = "Network activity"
    value: str
    to_ids: bool
    first_seen: str
    last_seen: str
    comment: str

    def payload(self) -> dict[str, Any]:
        return {
            "uuid": str(self.uuid),
            "type": self.type,
            "category": self.category,
            "value": self.value,
            "to_ids": self.to_ids,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "comment": self.comment,
            "distribution": "5",
        }


class MispEvent(BaseModel):
    """One aggregate MISP event for a window. Attributes are added separately."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    uuid: UUID
    info: str
    date: str
    distribution: str
    sharing_group_id: str | None = None
    threat_level_id: str = "3"
    analysis: str = "0"
    published: bool = False
    attributes: tuple[MispAttribute, ...] = ()
    tags: tuple[str, ...] = ()

    @field_validator("date")
    @classmethod
    def _date_only(cls, value: str) -> str:
        datetime.strptime(value, "%Y-%m-%d")
        return value

    def payload(self) -> dict[str, Any]:
        event: dict[str, Any] = {
            "uuid": str(self.uuid),
            "info": self.info,
            "date": self.date,
            "distribution": self.distribution,
            "threat_level_id": self.threat_level_id,
            "analysis": self.analysis,
            "published": self.published,
        }
        if self.sharing_group_id is not None:
            event["sharing_group_id"] = self.sharing_group_id
        if self.attributes:
            event["Attribute"] = [attribute.payload() for attribute in self.attributes]
        return event


class MispExistingEvent(BaseModel):
    """The part of a previously created event the publisher needs for retries."""

    model_config = ConfigDict(extra="ignore", frozen=True)

    id: int | None = None
    uuid: UUID
    distribution: str = ""
    attribute_values: frozenset[str] = frozenset()
    to_ids_values: frozenset[str] = frozenset()
    tags: frozenset[str] = frozenset()
    published: bool = False


class MispExistingAttribute(BaseModel):
    """Exact `ip-src` attribute match returned by MISP restSearch."""

    model_config = ConfigDict(extra="ignore", frozen=True)

    id: int
    value: str
    type: str = "ip-src"


class MispWindowResult(BaseModel):
    """Outcome of processing one queued window."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    window_start: datetime
    event_uuid: UUID | None = None
    event_id: int | None = None
    attributes: int = 0
    sightings: int = 0
    skipped: int = 0
    published: bool = False
    total_events: int = 0


def window_bounds(moment: datetime, seconds: int) -> tuple[datetime, datetime]:
    """Floor `moment` to a fixed UTC window and return `(start, end)`."""
    epoch = int(utc(moment).timestamp())
    start_epoch = epoch - (epoch % seconds)
    start = datetime.fromtimestamp(start_epoch, tz=UTC)
    return start, start + timedelta(seconds=seconds)


__all__ = [
    "MispAttribute",
    "MispEvent",
    "MispExistingAttribute",
    "MispExistingEvent",
    "MispObservation",
    "MispWindow",
    "MispWindowResult",
    "iso",
    "utc",
    "window_bounds",
]
