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
from collections.abc import Sequence
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
from opencanary_correlator.core.engine import CorrelationEngine
from opencanary_correlator.core.incident import IncidentRepository
from opencanary_correlator.core.rules import build_rules
from opencanary_correlator.core.windows import DedupCache
from opencanary_correlator.health import HealthServer
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
    """Build settings from the legacy file, the environment and CLI overrides."""
    settings = Settings.from_legacy_json(args.config) if args.config else Settings()
    overrides: dict[str, Any] = {}
    if args.redis_url:
        overrides["redis_url"] = args.redis_url
    if args.log_level:
        overrides["log_level"] = args.log_level.upper()
    if args.health_port is not None:
        overrides["health_port"] = args.health_port if args.health_port > 0 else None
    if overrides:
        settings = Settings(_env_file=None, **{**settings.model_dump(), **overrides})
    return settings


def safe_redis_url(url: str) -> str:
    """Return a Redis URL with the password replaced, for logs and `--check-config`."""
    parts = urlsplit(url)
    if parts.password:
        netloc = f"{parts.username}:***@{parts.hostname}"
        if parts.port:
            netloc += f":{parts.port}"
        parts = parts._replace(netloc=netloc)
    return urlunsplit(parts)


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
        "health_port": settings.health_port,
        "incident_horizon": settings.incident_horizon,
        "incident_horizons": settings.incident_horizons,
        "max_stored_events": settings.max_stored_events,
        "dispatch_timeout": settings.dispatch_timeout,
        "channels": channel_names(settings),
        "log_level": settings.log_level,
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

    for url in settings.webhook_urls:
        dispatchers.append(
            WebhookDispatcher(url=url, timeout=timeout, breaker=breaker("webhook", url))
        )
    if settings.slack_enabled:
        for slack_url in settings.slack_webhooks:
            dispatchers.append(
                SlackDispatcher(url=slack_url, timeout=timeout, breaker=breaker("slack", slack_url))
            )
    for discord_url in settings.discord_webhooks:
        dispatchers.append(
            DiscordDispatcher(
                url=discord_url, timeout=timeout, breaker=breaker("discord", discord_url)
            )
        )
    if settings.telegram_token is not None:
        for chat_id in settings.telegram_chat_ids:
            dispatchers.append(
                TelegramDispatcher(
                    token=settings.telegram_token,
                    chat_id=chat_id,
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
                username=settings.smtp_username,
                password=settings.smtp_password,
                start_tls=settings.smtp_starttls,
                use_tls=settings.smtp_use_tls,
                timeout=timeout,
            )
        )
    return dispatchers


def build_receivers(
    settings: Settings,
    engine: CorrelationEngine,
    audit: AuditLogger,
    rate_limiter: RedisRateLimiter | None,
) -> list[BaseReceiver]:
    """Instantiate every receiver enabled by the configuration."""
    receivers: list[BaseReceiver] = []
    if settings.tcp_enabled:
        receivers.append(
            TCPJSONReceiver(
                sink=engine,
                audit=audit,
                host=settings.tcp_host,
                port=settings.tcp_port,
                max_line_bytes=settings.max_line_bytes,
                partial_line_timeout=settings.partial_line_timeout,
                max_connections=settings.max_connections,
                queue_size=settings.event_queue_size,
                rate_limiter=rate_limiter,
                concurrency=settings.event_concurrency,
            )
        )
    if settings.syslog_enabled:
        receivers.append(
            SyslogTCPReceiver(
                sink=engine,
                audit=audit,
                host=settings.syslog_host,
                port=settings.syslog_port,
                max_line_bytes=settings.max_line_bytes,
                partial_line_timeout=settings.partial_line_timeout,
                max_connections=settings.max_connections,
                queue_size=settings.event_queue_size,
                rate_limiter=rate_limiter,
                concurrency=settings.event_concurrency,
            )
        )
        if settings.syslog_udp_enabled:
            receivers.append(
                SyslogUDPReceiver(
                    sink=engine,
                    audit=audit,
                    host=settings.syslog_host,
                    port=settings.syslog_port,
                    max_line_bytes=settings.max_line_bytes,
                    queue_size=settings.event_queue_size,
                    rate_limiter=rate_limiter,
                    concurrency=settings.event_concurrency,
                )
            )
    return receivers


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
    engine = CorrelationEngine(
        rules=build_rules(store, repository, settings),
        dispatchers=active_dispatchers,
        dedup=DedupCache(store, ttl=settings.dedup_ttl),
        settings=settings,
        audit=audit,
    )
    rate_limiter = (
        RedisRateLimiter(store, events_per_minute=settings.rate_limit_events_per_minute)
        if settings.rate_limit_events_per_minute > 0
        else None
    )
    receivers = build_receivers(settings, engine, audit, rate_limiter)
    health = health or (
        HealthServer(store, port=settings.health_port, audit=audit)
        if settings.health_port is not None
        else None
    )
    stop = stop_event or asyncio.Event()
    install_signal_handlers(stop)
    log_handler = RedisLogHandler(store)
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

    logging.basicConfig(level=settings.log_level)

    if args.check_config:
        print(json.dumps(describe_settings(settings), indent=2))
        return 0

    try:
        asyncio.run(run_correlator(settings))
    except CorrelatorStartupError as exc:
        print(f"cannot start: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:  # pragma: no cover - interactive shutdown
        return 0
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
