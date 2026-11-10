"""Build one aggregate MISP event per window without leaking honeypot material."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Final
from uuid import NAMESPACE_URL, UUID, uuid5

from opencanary_correlator.connectors.publishers.misp.models import (
    MispAttribute,
    MispEvent,
    MispObservation,
    MispWindow,
    iso,
)

#: The comment is generated only from fixed vocabulary and integers, so raw
#: log data, passwords, URLs and user agents cannot reach MISP.
_COMMENT_TEMPLATE: Final[str] = (
    "OpenCanary honeypot observation; {events} events across {services}; "
    "targeted port(s) {ports}.{geo} Automated observation, not an attributed "
    "actor. No credentials, payloads or raw logs were shared."
)


def event_uuid(namespace: str, start: datetime) -> UUID:
    """Deterministic event UUID: a retry addresses the same event, never a duplicate."""
    epoch = int(start.astimezone(UTC).timestamp())
    return uuid5(NAMESPACE_URL, f"opencanary:{namespace}:misp-event:{epoch}")


def attribute_uuid(event_id: UUID, ip: str) -> UUID:
    """Deterministic attribute UUID within its event."""
    return uuid5(event_id, ip)


class MispEventBuilder:
    """Pure builder; it never calls MISP and never reads an incident's log data."""

    def __init__(
        self,
        *,
        namespace: str,
        distribution: int = 0,
        sharing_group_id: int | None = None,
        tlp: str = "amber",
        pap: str = "amber",
        confidence_tag: str = 'misp:confidence-level="rarely-confident"',
        source_tags: tuple[str, ...] = ("honeypot",),
        to_ids_types: frozenset[str] = frozenset(),
        to_ids_min_events: int = 3,
    ) -> None:
        self._namespace = namespace
        self._distribution = distribution
        self._sharing_group_id = sharing_group_id
        self._tlp = tlp
        self._pap = pap
        self._confidence_tag = confidence_tag
        self._source_tags = source_tags
        self._to_ids_types = to_ids_types
        self._to_ids_min_events = to_ids_min_events

    @property
    def tags(self) -> tuple[str, ...]:
        return (
            f"tlp:{self._tlp}",
            f"pap:{self._pap}",
            self._confidence_tag,
            *self._source_tags,
        )

    @staticmethod
    def _clean_geo(value: str, limit: int) -> str:
        """Remove control characters from an MMDB string before it reaches MISP."""
        return "".join(
            character for character in value if ord(character) >= 32 and character != "\x7f"
        )[:limit]

    def _comment(self, observation: MispObservation) -> str:
        services = (
            ", ".join(f"{name} ({count})" for name, count in sorted(observation.services.items()))
            or "unknown"
        )
        ports = ", ".join(str(port) for port in sorted(observation.ports)) or "unknown"
        geo = ""
        if observation.country_code or observation.asn or observation.as_org:
            network = self._clean_geo(observation.as_org, 120)
            if observation.asn:
                network = f"AS{observation.asn}" + (f" {network}" if network else "")
            location = self._clean_geo(observation.country_code, 2)
            geo = (
                " Country/network: "
                + ", ".join(value for value in (location, network) if value)
                + "."
            )
        return _COMMENT_TEMPLATE.format(
            events=observation.count,
            services=services[:500],
            ports=ports[:200],
            geo=geo,
        )

    def _to_ids(self, observation: MispObservation) -> bool:
        if observation.count < self._to_ids_min_events:
            return False
        if not self._to_ids_types:
            return False
        # A mixed-service address gets the flag only for an explicitly listed
        # auth service; unrelated scan or HTTP-request traffic cannot force it.
        return any(name in self._to_ids_types for name in observation.services)

    def build(self, window: MispWindow) -> MispEvent:
        """Build the aggregate event and all its attributes."""
        start = window.start.astimezone(UTC)
        identifier = event_uuid(self._namespace, start)
        attributes = tuple(
            MispAttribute(
                uuid=attribute_uuid(identifier, observation.ip),
                value=observation.ip,
                to_ids=self._to_ids(observation),
                first_seen=iso(observation.first_seen),
                last_seen=iso(observation.last_seen),
                comment=self._comment(observation),
            )
            for observation in window.observations
        )
        return MispEvent(
            uuid=identifier,
            info=(
                "OpenCanary honeypot observations "
                f"{start.date().isoformat()} UTC ({len(attributes)} source addresses)"
            ),
            date=start.date().isoformat(),
            distribution=str(self._distribution),
            sharing_group_id=(
                str(self._sharing_group_id) if self._sharing_group_id is not None else None
            ),
            attributes=attributes,
            tags=self.tags,
        )


__all__ = ["MispEventBuilder", "attribute_uuid", "event_uuid"]
