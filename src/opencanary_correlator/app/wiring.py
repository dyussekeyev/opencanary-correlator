"""What the settings turn into: enrichment, listeners, rate limit and health.

Delivery channels live in `app.channels`; this module covers the rest of the
runtime objects the engine and the process need.
"""

from __future__ import annotations

from typing import Any

from opencanary_correlator.app.parser import CorrelatorStartupError
from opencanary_correlator.audit import AuditLogger
from opencanary_correlator.config import Settings
from opencanary_correlator.connectors.base import BaseReceiver
from opencanary_correlator.connectors.receivers import (
    SyslogTCPReceiver,
    SyslogUDPReceiver,
    TCPJSONReceiver,
)
from opencanary_correlator.connectors.receivers._allowlist import parse_allowed_networks
from opencanary_correlator.core.engine import CorrelationEngine
from opencanary_correlator.core.service_messages import ServiceNotifier
from opencanary_correlator.enrichment import (
    GeoLookup,
    GeoLookupError,
    IncidentEnricher,
    QuotaLimits,
    VirusTotalClient,
)
from opencanary_correlator.health import HealthServer
from opencanary_correlator.storage.rate_limit import RedisRateLimiter
from opencanary_correlator.storage.redis_store import RedisStore


def build_enricher(
    settings: Settings,
    store: RedisStore,
    audit: AuditLogger,
    notifier: ServiceNotifier | None = None,
) -> IncidentEnricher | None:
    """Build the attacker-IP enricher, or None when nothing is configured.

    A configured geo database that cannot be opened stops startup: the operator
    asked for country data and would otherwise get alerts without it, with no
    hint about why. VirusTotal needs a key, which is also the consent to send
    attacker addresses to a third party.
    """
    geo: GeoLookup | None = None
    if settings.geoip_city_db or settings.geoip_asn_db:
        try:
            geo = GeoLookup.open(settings.geoip_city_db, settings.geoip_asn_db)
        except GeoLookupError as exc:
            raise CorrelatorStartupError(f"geoip database: {exc}") from exc

    virustotal: VirusTotalClient | None = None
    if settings.virustotal_api_key is not None:
        virustotal = VirusTotalClient(
            api_key=settings.virustotal_api_key,
            store=store,
            cache_ttl=settings.virustotal_cache_ttl,
            timeout=settings.virustotal_timeout,
            limits=QuotaLimits(
                per_minute=settings.virustotal_per_minute,
                per_day=settings.virustotal_per_day,
                per_month=settings.virustotal_per_month,
            ),
        )
    if geo is None and virustotal is None:
        return None
    return IncidentEnricher(
        geo=geo,
        virustotal=virustotal,
        audit=audit,
        timeout=settings.enrichment_timeout,
        notifier=notifier,
    )


def build_receivers(
    settings: Settings,
    engine: CorrelationEngine,
    audit: AuditLogger,
    rate_limiter: RedisRateLimiter | None,
) -> list[BaseReceiver]:
    """Instantiate every receiver enabled by the configuration."""
    receivers: list[BaseReceiver] = []
    allowed_networks = parse_allowed_networks(settings.receiver_allowed_ips)
    # Arguments shared by every listener; each receiver adds its own host/port.
    common: dict[str, Any] = {
        "sink": engine,
        "audit": audit,
        "max_line_bytes": settings.max_line_bytes,
        "queue_size": settings.event_queue_size,
        "rate_limiter": rate_limiter,
        "concurrency": settings.event_concurrency,
        "allowed_networks": allowed_networks,
    }
    # Stream receivers additionally take the connection-level limits.
    stream: dict[str, Any] = {
        **common,
        "partial_line_timeout": settings.partial_line_timeout,
        "max_connections": settings.max_connections,
    }
    if settings.tcp_enabled:
        receivers.append(TCPJSONReceiver(host=settings.tcp_host, port=settings.tcp_port, **stream))
    if settings.syslog_enabled:
        receivers.append(
            SyslogTCPReceiver(host=settings.syslog_host, port=settings.syslog_port, **stream)
        )
        if settings.syslog_udp_enabled:
            receivers.append(
                SyslogUDPReceiver(host=settings.syslog_host, port=settings.syslog_port, **common)
            )
    return receivers


def build_rate_limiter(settings: Settings, store: RedisStore) -> RedisRateLimiter | None:
    """Return the shared event rate limiter, or None when it is disabled."""
    if settings.rate_limit_events_per_minute <= 0:
        return None
    return RedisRateLimiter(store, events_per_minute=settings.rate_limit_events_per_minute)


def build_health_server(
    settings: Settings, store: RedisStore, audit: AuditLogger
) -> HealthServer | None:
    """Return the health endpoint server, or None when no port is configured."""
    if settings.health_port is None:
        return None
    return HealthServer(
        store,
        host=settings.health_host,
        port=settings.health_port,
        audit=audit,
        allowed_networks=parse_allowed_networks(settings.health_allowed_ips),
    )


__all__ = [
    "build_enricher",
    "build_health_server",
    "build_rate_limiter",
    "build_receivers",
]
