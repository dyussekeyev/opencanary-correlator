"""The process: signal handling, the supervised task set and the exit codes."""

from __future__ import annotations

import asyncio
import json
import logging
import signal
import sys
from collections.abc import Sequence

from pydantic import ValidationError

from opencanary_correlator.app.channels import build_dispatchers
from opencanary_correlator.app.describe import describe_settings, log_secrets
from opencanary_correlator.app.parser import CorrelatorStartupError, build_parser, load_settings
from opencanary_correlator.app.wiring import (
    build_enricher,
    build_health_server,
    build_rate_limiter,
    build_receivers,
)
from opencanary_correlator.audit import AuditLogger, RedisLogHandler
from opencanary_correlator.config import Settings
from opencanary_correlator.connectors.base import BaseDispatcher, BaseReceiver
from opencanary_correlator.core.budget import AlertBudget
from opencanary_correlator.core.engine import CorrelationEngine
from opencanary_correlator.core.incident import IncidentRepository
from opencanary_correlator.core.outbox import AlertOutbox
from opencanary_correlator.core.rules import build_rules
from opencanary_correlator.core.windows import DedupCache
from opencanary_correlator.health import HealthServer
from opencanary_correlator.log_setup import (
    LOG_DATE_FORMAT,
    LogSetupError,
    RedactingFormatter,
    SecretRedactionFilter,
    SingleLineFilter,
    configure_logging,
)
from opencanary_correlator.storage.redis_store import RedisStore

_logger = logging.getLogger(__name__)


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

    active_dispatchers = (
        list(dispatchers) if dispatchers is not None else build_dispatchers(settings, store)
    )
    # Built before the repository: a new incident owes a delivery to every channel
    # the outbox knows, and the incident and those debts are written together.
    outbox = (
        AlertOutbox(store, active_dispatchers, settings, audit) if settings.outbox_enabled else None
    )
    repository = IncidentRepository(
        store,
        settings,
        audit,
        alert_channels=outbox.channels if outbox is not None else (),
    )
    # The budget rations notifications, so it needs the channels it summarises
    # through; with the budget off, `None` keeps the old behaviour exactly.
    budget = (
        AlertBudget(store, active_dispatchers, settings, audit)
        if settings.alert_budget_enabled
        else None
    )
    enricher = build_enricher(settings, store, audit)
    engine = CorrelationEngine(
        rules=build_rules(store, repository, settings),
        dispatchers=active_dispatchers,
        dedup=DedupCache(store, ttl=settings.dedup_ttl, lease=settings.dedup_lease),
        settings=settings,
        audit=audit,
        enricher=enricher,
        outbox=outbox,
        budget=budget,
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
    # The package root, not this module: every correlator record must reach the
    # journal, which is what `opencanary_correlator.*` loggers propagate to.
    package_logger = logging.getLogger("opencanary_correlator")
    package_logger.addHandler(log_handler)

    started: list[BaseReceiver] = []
    try:
        await log_handler.start()
        for receiver in receivers:
            await receiver.start()
            started.append(receiver)
        if health is not None:
            await health.start()
        if outbox is not None:
            await outbox.start()
        if budget is not None:
            await budget.start()
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
        if outbox is not None:
            await outbox.stop()
        if budget is not None:
            await budget.stop()
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


__all__ = ["install_signal_handlers", "main", "run_correlator"]
