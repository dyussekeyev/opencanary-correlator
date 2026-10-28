"""Command-line entry point and runtime wiring.

`run_correlator` accepts injected dependencies so the full stack can be tested
without a live Redis server.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import signal
import sys
from collections.abc import Callable, Sequence
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from pydantic import ValidationError

from opencanary_correlator import __version__
from opencanary_correlator.audit import AuditLogger, RedisLogHandler
from opencanary_correlator.config import Settings
from opencanary_correlator.connectors.base import BaseDispatcher, BaseReceiver
from opencanary_correlator.connectors.dispatchers import (
    CircuitBreaker,
    DiscordDispatcher,
    SlackDispatcher,
    SmtpDispatcher,
    TelegramDispatcher,
    WebhookDispatcher,
    breaker_name,
)
from opencanary_correlator.connectors.receivers import (
    SyslogTCPReceiver,
    SyslogUDPReceiver,
    TCPJSONReceiver,
)
from opencanary_correlator.connectors.receivers._allowlist import parse_allowed_networks
from opencanary_correlator.core.engine import CorrelationEngine
from opencanary_correlator.core.incident import IncidentRepository
from opencanary_correlator.core.rules import build_rules
from opencanary_correlator.core.windows import DedupCache
from opencanary_correlator.enrichment import (
    GeoLookup,
    GeoLookupError,
    IncidentEnricher,
    QuotaLimits,
    VirusTotalClient,
)
from opencanary_correlator.health import HealthServer
from opencanary_correlator.log_setup import (
    LOG_DATE_FORMAT,
    LogSetupError,
    RedactingFormatter,
    SecretRedactionFilter,
    SingleLineFilter,
    configure_logging,
)
from opencanary_correlator.storage.rate_limit import RedisRateLimiter
from opencanary_correlator.storage.redis_store import RedisStore

PROG = "opencanary-correlator"
_logger = logging.getLogger(__name__)


class CorrelatorStartupError(RuntimeError):
    """Raised when the correlator cannot start (for example Redis is down)."""


def build_parser() -> argparse.ArgumentParser:
    """Return the argument parser for the correlator executable."""
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="Stateless OpenCanary event correlator",
    )
    parser.add_argument("--version", action="version", version=f"{PROG} {__version__}")
    parser.add_argument(
        "--config",
        metavar="PATH",
        help="legacy JSON configuration file (migrated on startup)",
    )
    parser.add_argument("--redis-url", help="override OCC_REDIS_URL")
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="override OCC_LOG_LEVEL",
    )
    parser.add_argument(
        "--log-file",
        metavar="PATH",
        help="override OCC_LOG_FILE (adds a rotated log file next to stderr)",
    )
    parser.add_argument(
        "--health-port",
        type=int,
        help="override OCC_HEALTH_PORT (0 disables the endpoint)",
    )
    parser.add_argument(
        "--check-config",
        action="store_true",
        help="validate configuration and exit",
    )
    return parser


def load_settings(args: argparse.Namespace) -> Settings:
    """Build settings from the legacy file, the environment and CLI overrides.

    The overrides are handed to the constructor instead of being merged into an
    already-built settings object: `redis_url` has no default, so a flag that is
    meant to supply it has to be visible to validation. Merging afterwards made
    `opencanary-correlator --redis-url redis://host:6379/0` exit 2 with
    "redis_url: Field required" unless the variable was also exported.
    """
    overrides: dict[str, Any] = {}
    if args.redis_url:
        overrides["redis_url"] = args.redis_url
    if args.log_level:
        overrides["log_level"] = args.log_level.upper()
    if args.log_file:
        overrides["log_file"] = args.log_file
    if args.health_port is not None:
        overrides["health_port"] = args.health_port if args.health_port > 0 else None
    if args.config:
        return Settings.from_legacy_json(args.config, overrides=overrides)
    return Settings(**overrides)


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
    """
    secrets: list[str] = []
    for url in (*settings.webhook_urls, *settings.slack_webhooks, *settings.discord_webhooks):
        parts = urlsplit(url)
        tail = parts.path if not parts.query else f"{parts.path}?{parts.query}"
        if len(tail) > 1:  # a bare "/" carries no secret
            secrets.append(tail)
    if settings.telegram_token is not None:
        secrets.append(settings.telegram_token.get_secret_value())
    if settings.smtp_password is not None:
        secrets.append(settings.smtp_password.get_secret_value())
    return tuple(secrets)


def describe_settings(settings: Settings) -> dict[str, Any]:
    """Return a secret-free summary of the effective configuration."""
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
        "alert_detail": {
            "telegram": settings.telegram_detail,
            "slack": settings.slack_detail,
            "discord": settings.discord_detail,
            "webhook": settings.webhook_detail,
            "smtp": settings.smtp_detail,
        },
        "channels": channel_names(settings),
        "enrichment": {
            "geoip": bool(settings.geoip_city_db or settings.geoip_asn_db),
            "virustotal": settings.virustotal_api_key is not None,
        },
        "log_level": settings.log_level,
        "log_file": settings.log_file,
    }


def channel_names(settings: Settings) -> list[str]:
    """Names of the dispatchers that the configuration would enable."""
    channels: list[str] = []
    channels.extend("webhook" for _ in settings.webhook_urls)
    if settings.slack_enabled:
        channels.extend("slack" for _ in settings.slack_webhooks)
    channels.extend("discord" for _ in settings.discord_webhooks)
    if settings.telegram_token is not None:
        channels.extend("telegram" for _ in settings.telegram_chat_ids)
    if settings.smtp_enabled and settings.smtp_host and settings.smtp_to:
        channels.append("smtp")
    return channels


def build_dispatchers(settings: Settings, store: RedisStore) -> list[BaseDispatcher]:
    """Instantiate every dispatcher enabled by the configuration."""
    dispatchers: list[BaseDispatcher] = []
    timeout = settings.dispatch_timeout

    def breaker(channel: str, endpoint: str) -> CircuitBreaker:
        return CircuitBreaker(store, breaker_name(channel, endpoint))

    def add_endpoints(
        channel: str,
        urls: Sequence[str],
        factory: Callable[..., BaseDispatcher],
        detail: str,
    ) -> None:
        # One dispatcher per URL, each guarded by its own circuit breaker.
        for url in urls:
            dispatchers.append(
                factory(
                    url=url,
                    timeout=timeout,
                    breaker=breaker(channel, url),
                    detail=detail,
                )
            )

    add_endpoints("webhook", settings.webhook_urls, WebhookDispatcher, settings.webhook_detail)
    if settings.slack_enabled:
        add_endpoints("slack", settings.slack_webhooks, SlackDispatcher, settings.slack_detail)
    elif settings.slack_webhooks:
        # The opposite of the startup error: a webhook with the switch off would
        # otherwise be ignored without a word.
        _logger.warning(
            "OCC_SLACK_WEBHOOKS is set but OCC_SLACK_ENABLED is false: Slack alerts are disabled"
        )
    add_endpoints("discord", settings.discord_webhooks, DiscordDispatcher, settings.discord_detail)
    if settings.telegram_token is not None:
        for chat_id in settings.telegram_chat_ids:
            dispatchers.append(
                TelegramDispatcher(
                    token=settings.telegram_token,
                    chat_id=chat_id,
                    detail=settings.telegram_detail,
                    timeout=timeout,
                    breaker=breaker("telegram", chat_id),
                )
            )
    if settings.smtp_enabled and settings.smtp_host and settings.smtp_to:
        dispatchers.append(
            SmtpDispatcher(
                host=settings.smtp_host,
                port=settings.smtp_port,
                sender=settings.smtp_from,
                recipients=settings.smtp_to,
                detail=settings.smtp_detail,
                username=settings.smtp_username,
                password=settings.smtp_password,
                start_tls=settings.smtp_starttls,
                use_tls=settings.smtp_use_tls,
                timeout=timeout,
            )
        )
    return dispatchers


def build_enricher(
    settings: Settings, store: RedisStore, audit: AuditLogger
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
        geo=geo, virustotal=virustotal, audit=audit, timeout=settings.enrichment_timeout
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


def install_signal_handlers(stop_event: asyncio.Event) -> None:
    """Stop the correlator on SIGINT/SIGTERM, on every supported platform."""
    loop = asyncio.get_running_loop()

    def _request_stop(*_args: object) -> None:
        loop.call_soon_threadsafe(stop_event.set)

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except (NotImplementedError, RuntimeError):
            try:
                signal.signal(sig, _request_stop)
            except (ValueError, OSError):  # pragma: no cover - restricted platforms
                _logger.debug("cannot install handler for %s", sig)


async def run_correlator(
    settings: Settings,
    *,
    store: RedisStore | None = None,
    dispatchers: Sequence[BaseDispatcher] | None = None,
    audit: AuditLogger | None = None,
    stop_event: asyncio.Event | None = None,
    health: HealthServer | None = None,
) -> None:
    """Run receivers, correlation and dispatchers until `stop_event` is set."""
    audit = audit or AuditLogger("correlator")
    owns_store = store is None
    store = store or RedisStore.from_url(settings.redis_url)
    if not await store.ping():
        audit.emit("startup_failed", "error", {"reason": "redis_unavailable"})
        if owns_store:
            await store.aclose()
        raise CorrelatorStartupError("Redis is not reachable")

    repository = IncidentRepository(store, settings, audit)
    active_dispatchers = (
        list(dispatchers) if dispatchers is not None else build_dispatchers(settings, store)
    )
    enricher = build_enricher(settings, store, audit)
    engine = CorrelationEngine(
        rules=build_rules(store, repository, settings),
        dispatchers=active_dispatchers,
        dedup=DedupCache(store, ttl=settings.dedup_ttl),
        settings=settings,
        audit=audit,
        enricher=enricher,
    )
    rate_limiter = build_rate_limiter(settings, store)
    receivers = build_receivers(settings, engine, audit, rate_limiter)
    health = health or build_health_server(settings, store, audit)
    stop = stop_event or asyncio.Event()
    install_signal_handlers(stop)
    log_handler = RedisLogHandler(store)
    # The legacy console journal is a log sink too: it keeps its bare-message
    # format but gets the same flattening and secret redaction as stderr and the
    # file, so the console and Redis never show what those two mask.
    secrets = log_secrets(settings)
    log_handler.addFilter(SingleLineFilter())
    log_handler.addFilter(SecretRedactionFilter(secrets))
    log_handler.setFormatter(
        RedactingFormatter("%(message)s", datefmt=LOG_DATE_FORMAT, secrets=secrets)
    )
    package_logger = logging.getLogger(__package__)
    package_logger.addHandler(log_handler)

    started: list[BaseReceiver] = []
    try:
        await log_handler.start()
        for receiver in receivers:
            await receiver.start()
            started.append(receiver)
        if health is not None:
            await health.start()
        audit.emit(
            "startup",
            "info",
            {
                "receivers": [receiver.name for receiver in receivers],
                "rules": list(engine.rule_names),
                "channels": [dispatcher.name for dispatcher in active_dispatchers],
            },
        )
        await stop.wait()
    except Exception as exc:
        audit.emit("startup_failed", "error", {"error_type": type(exc).__name__})
        raise
    finally:
        for receiver in reversed(started):
            await receiver.stop()
        if health is not None:
            await health.stop()
        await asyncio.gather(
            *(dispatcher.aclose() for dispatcher in active_dispatchers),
            return_exceptions=True,
        )
        if enricher is not None:
            await enricher.aclose()
        package_logger.removeHandler(log_handler)
        await log_handler.stop()
        if owns_store:
            await store.aclose()
        audit.emit("shutdown", "info", {"receivers": len(started)})


def main(argv: Sequence[str] | None = None) -> int:
    """Run the correlator."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        settings = load_settings(args)
    except ValidationError as exc:
        print("invalid configuration:", file=sys.stderr)
        for error in exc.errors():
            location = ".".join(str(part) for part in error["loc"]) or "settings"
            print(f"  {location}: {error['msg']}", file=sys.stderr)
        return 2
    except (OSError, ValueError) as exc:
        print(f"cannot load configuration: {exc}", file=sys.stderr)
        return 2

    try:
        configure_logging(settings.log_level, settings.log_file, secrets=log_secrets(settings))
    except LogSetupError as exc:
        print(f"cannot open the log file: {exc}", file=sys.stderr)
        return 2

    if args.check_config:
        print(json.dumps(describe_settings(settings), indent=2))
        return 0

    try:
        asyncio.run(run_correlator(settings))
    except CorrelatorStartupError as exc:
        # Through the logger, not print(): a startup failure must reach the log
        # file too, otherwise the file an operator just configured is empty on
        # the one occasion they need it.
        _logger.critical("cannot start: %s", exc)
        return 1
    except KeyboardInterrupt:  # pragma: no cover - interactive shutdown
        return 0
    except Exception:
        # An unhandled crash would otherwise go to stderr only and leave the
        # log file with no traceback at all.
        _logger.exception("correlator stopped on an unhandled error")
        return 1
    return 0


__all__ = [
    "CorrelatorStartupError",
    "build_dispatchers",
    "build_parser",
    "build_receivers",
    "channel_names",
    "describe_settings",
    "install_signal_handlers",
    "load_settings",
    "main",
    "run_correlator",
    "safe_redis_url",
]
