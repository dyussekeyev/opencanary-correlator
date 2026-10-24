"""Port-scan detection.

Both rules replace the legacy non-atomic ``exists``/``sadd``/``scard``
sequences with a single Redis-backed distinct-set window, so replicas cannot
race each other into duplicate incidents.
"""

from __future__ import annotations

from typing import ClassVar

from opencanary_correlator.config import Settings
from opencanary_correlator.constants import (
    INCIDENT_LOGTYPE_HOST_PORT_SCAN,
    INCIDENT_LOGTYPE_NETWORK_PORT_SCAN,
    LogType,
)
from opencanary_correlator.core.incident import Incident, IncidentRepository
from opencanary_correlator.core.rules.base import Rule
from opencanary_correlator.core.windows import DistinctSetWindow
from opencanary_correlator.schemas import CanaryEvent
from opencanary_correlator.storage import keys
from opencanary_correlator.storage.redis_store import RedisStore


class HostPortScanRule(Rule):
    """Incident when one canary sees SYN packets to many ports of one target."""

    name: ClassVar[str] = "host_portscan"

    def __init__(
        self,
        *,
        store: RedisStore,
        repository: IncidentRepository,
        settings: Settings,
    ) -> None:
        self._store = store
        self._repository = repository
        self._settings = settings

    def matches(self, event: CanaryEvent) -> bool:
        """True for SYN packet reports."""
        return int(event.logtype) == int(LogType.LOG_PORT_SYN)

    async def apply(self, event: CanaryEvent, *, now: float) -> list[Incident]:
        """Track distinct destination ports and fire at the configured threshold."""
        window = DistinctSetWindow(
            self._store,
            keys.host_scan_key(event.src_host, event.dst_host),
            ttl=float(self._settings.scan_host_horizon),
        )
        count = await window.add(str(event.dst_port))
        if count < self._settings.scan_host_threshold:
            return []

        ports = await window.members()
        await window.clear()
        incident = await self._repository.record(
            "scans.host_portscan",
            event,
            logdata=sorted(int(port) for port in ports),
            logtype=INCIDENT_LOGTYPE_HOST_PORT_SCAN,
        )
        return [incident] if incident is not None else []


class NetworkPortScanRule(Rule):
    """Incident when one source host is seen scanning several canaries on one port."""

    name: ClassVar[str] = "network_portscan"

    def __init__(
        self,
        *,
        store: RedisStore,
        repository: IncidentRepository,
        settings: Settings,
    ) -> None:
        self._store = store
        self._repository = repository
        self._settings = settings

    def matches(self, event: CanaryEvent) -> bool:
        """True for SYN packet reports."""
        return int(event.logtype) == int(LogType.LOG_PORT_SYN)

    async def apply(self, event: CanaryEvent, *, now: float) -> list[Incident]:
        """Track distinct targets per source host and destination port."""
        target = event.reported_dst_host or event.dst_host
        window = DistinctSetWindow(
            self._store,
            keys.network_scan_key(event.src_host, event.dst_port),
            ttl=float(self._settings.scan_network_horizon),
        )
        count = await window.add(target)
        if count < self._settings.scan_network_threshold:
            return []

        targets = await window.members()
        incident = await self._repository.record(
            "scans.network_portscan",
            event,
            logdata=sorted(targets),
            logtype=INCIDENT_LOGTYPE_NETWORK_PORT_SCAN,
        )
        return [incident] if incident is not None else []


__all__ = ["HostPortScanRule", "NetworkPortScanRule"]
