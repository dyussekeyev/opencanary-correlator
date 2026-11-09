"""Turn correlated incidents into deliberately small MISP observations."""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime
from typing import Protocol

from opencanary_correlator.connectors.publishers.misp.models import MispObservation


class ObservationIncident(Protocol):
    """The fields an incident must expose for MISP observation extraction."""

    src_host: str
    dst_port: int
    created: int
    events_list: str
    events_count: int
    INCIDENT_NAME: str


def _event_times(incident: ObservationIncident) -> tuple[datetime, datetime]:
    """Use the stored event timestamps, falling back to the incident creation time."""
    values: list[datetime] = []
    for raw in incident.events_list.split(","):
        text = raw.strip()
        if not text:
            continue
        try:
            values.append(datetime.fromtimestamp(int(text), tz=UTC))
        except (OverflowError, OSError, ValueError):
            continue
    if values:
        return min(values), max(values)
    created = datetime.fromtimestamp(incident.created, tz=UTC)
    return created, created


def observation_from_incident(
    incident: ObservationIncident,
    *,
    protected_addresses: frozenset[str] = frozenset(),
) -> MispObservation | None:
    """Build one observation, or return None when the source is not publishable.

    Only globally routable addresses are shared. A private, loopback, link-local,
    documentation or multicast address is either the operator's own estate or not
    attributable on the internet, and neither belongs in a community feed. The
    explicit protected set is the same honeypot identity inventory used by
    notification redaction.
    """
    raw = incident.src_host.strip()
    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        return None
    if not address.is_global or str(address) in protected_addresses:
        return None
    first_seen, last_seen = _event_times(incident)
    service = str(getattr(incident, "INCIDENT_NAME", "") or "opencanary")
    port = int(incident.dst_port)
    enrichment = getattr(incident, "enrichment", None)
    geo = getattr(enrichment, "geo", None) if enrichment is not None else None
    count = max(1, int(incident.events_count))
    return MispObservation(
        ip=str(address),
        first_seen=first_seen,
        last_seen=last_seen,
        count=count,
        services={service: count},
        ports={port: count} if 0 <= port <= 65535 else {},
        country_code=str(getattr(geo, "country_code", "") or "") if geo else "",
        country=str(getattr(geo, "country", "") or "") if geo else "",
        asn=getattr(geo, "asn", None) if geo else None,
        as_org=str(getattr(geo, "as_org", "") or "") if geo else "",
    )


__all__ = ["ObservationIncident", "observation_from_incident"]
