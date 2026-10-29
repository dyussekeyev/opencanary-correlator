"""The effective configuration, described without leaking a secret."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit, urlunsplit

from opencanary_correlator.app.channels import CHANNEL_SPECS, channel_names
from opencanary_correlator.config import Settings


def safe_redis_url(url: str) -> str:
    """Return a Redis URL with the password replaced, for logs and `--check-config`."""
    parts = urlsplit(url)
    if parts.password:
        netloc = f"{parts.username}:***@{parts.hostname}"
        if parts.port:
            netloc += f":{parts.port}"
        parts = parts._replace(netloc=netloc)
    return urlunsplit(parts)


def log_secrets(settings: Settings) -> tuple[str, ...]:
    """Values that must never survive into a log line.

    For webhook URLs only the path and query are returned: they hold the
    credential, while the scheme and host keep the line readable. That literal
    match is what covers an arbitrary webhook host whose secret sits in a path
    segment, which no URL pattern can recognise. The Telegram token is matched
    on its own, because the Bot API requires it inside the path of ``/bot<id>:<token>``
    and the pattern pass already knows that shape.

    The URL channels come from the same table that builds the dispatchers, so a
    channel added there is covered by redaction without a second edit.
    """
    secrets: list[str] = []
    for spec in CHANNEL_SPECS:
        if not spec.target_is_secret:
            continue
        for url in spec.targets(settings):
            parts = urlsplit(url)
            tail = parts.path if not parts.query else f"{parts.path}?{parts.query}"
            if len(tail) > 1:  # a bare "/" carries no secret
                secrets.append(tail)
    if settings.telegram_token is not None:
        secrets.append(settings.telegram_token.get_secret_value())
    if settings.smtp_password is not None:
        secrets.append(settings.smtp_password.get_secret_value())
    if settings.virustotal_api_key is not None:
        # Sent in a header, so httpx does not log it - but an exception carrying
        # the request, or any future library that logs headers, would.
        secrets.append(settings.virustotal_api_key.get_secret_value())
    return tuple(secrets)


def describe_settings(settings: Settings) -> dict[str, Any]:
    """Return a secret-free summary of the effective configuration.

    The channel list and the per-channel detail come from `CHANNEL_SPECS`, the
    same table `build_dispatchers` reads, so the summary cannot promise a
    delivery that startup would not build.
    """
    return {
        "redis_url": safe_redis_url(settings.redis_url),
        "tcp": {
            "enabled": settings.tcp_enabled,
            "host": settings.tcp_host,
            "port": settings.tcp_port,
        },
        "syslog": {
            "enabled": settings.syslog_enabled,
            "host": settings.syslog_host,
            "port": settings.syslog_port,
            "udp": settings.syslog_udp_enabled,
        },
        "health_host": settings.health_host,
        "health_port": settings.health_port,
        "health_allowed_ips": settings.health_allowed_ips,
        "incident_horizon": settings.incident_horizon,
        "incident_horizons": settings.incident_horizons,
        "max_stored_events": settings.max_stored_events,
        "incident_lookup_scan_limit": settings.incident_lookup_scan_limit,
        "dispatch_timeout": settings.dispatch_timeout,
        "alert_detail": {spec.name: spec.detail(settings) for spec in CHANNEL_SPECS},
        "channels": channel_names(settings),
        "enrichment": {
            "geoip": bool(settings.geoip_city_db or settings.geoip_asn_db),
            "virustotal": settings.virustotal_api_key is not None,
        },
        "alert_budget": {
            "enabled": settings.alert_budget_enabled,
            "per_node": settings.alert_budget_per_node,
            "global": settings.alert_budget_global,
            "window": settings.alert_budget_window,
        },
        "service_messages": {
            "enabled": settings.service_enabled,
            "channels": list(settings.service_channels),
            "categories": list(settings.service_categories),
            "cooldown": settings.service_cooldown,
            "min_severity": settings.service_min_severity,
        },
        "digest": {
            "enabled": settings.digest_enabled,
            "time": settings.digest_time,
            "channels": list(settings.digest_channels),
            "top_sources": settings.digest_top_sources,
        },
        "canary_silence": {
            "enabled": settings.canary_silent_after > 0,
            "after_seconds": settings.canary_silent_after,
            "check_interval": settings.watch_interval,
        },
        "ingestion_reports": {
            "drops_threshold": settings.service_drops_threshold,
            "rejections_threshold": settings.service_rejections_threshold,
            "window": settings.watch_interval,
        },
        "log_level": settings.log_level,
        "log_file": settings.log_file,
    }


__all__ = ["CHANNEL_SPECS", "channel_names", "describe_settings", "log_secrets", "safe_redis_url"]
