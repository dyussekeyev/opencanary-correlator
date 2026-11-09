"""The process: signal handling, the supervised task set and the exit codes."""

from __future__ import annotations

import asyncio
import json
import logging
import signal
import sys
import time
from collections.abc import Awaitable, Callable, Sequence

from pydantic import ValidationError

from opencanary_correlator import __version__
from opencanary_correlator.app.admin import run_admin
from opencanary_correlator.app.channels import build_dispatchers
from opencanary_correlator.app.describe import describe_settings, log_secrets
from opencanary_correlator.app.parser import CorrelatorStartupError, build_parser, load_settings
from opencanary_correlator.app.wiring import (
    build_enricher,
    build_health_server,
    build_publishers,
    build_rate_limiter,
    build_receivers,
)
from opencanary_correlator.audit import AuditLogger, RedisLogHandler
from opencanary_correlator.config import Settings
from opencanary_correlator.connectors.base import BaseDispatcher, BaseReceiver
from opencanary_correlator.connectors.publishers.base import BasePublisher
from opencanary_correlator.core.budget import AlertBudget
from opencanary_correlator.core.digest import DigestScheduler
from opencanary_correlator.core.engine import CorrelationEngine
from opencanary_correlator.core.incident import IncidentRepository
from opencanary_correlator.core.outbox import AlertOutbox
from opencanary_correlator.core.retention import RetentionJanitor
from opencanary_correlator.core.rules import build_rules
from opencanary_correlator.core.service_messages import (
    ServiceKind,
    ServiceNotifier,
)
from opencanary_correlator.core.stats import StatsReporter
from opencanary_correlator.core.watch import HealthWatch
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
from opencanary_correlator.presence import NodeRegistry
from opencanary_correlator.storage.redis_store import RedisStore

_logger = logging.getLogger(__name__)


def _require_configured_service_channels(
    settings: Settings, dispatchers: Sequence[BaseDispatcher]
) -> None:
    """Fail at startup when a service-message channel was never built.

    A name in `OCC_SERVICE_CHANNELS` that no dispatcher answers would silently
    drop every service message, which is the opposite of the feature's purpose.
    The check runs against the dispatchers startup actually built, so a channel
    that is configured but switched off counts as missing.
    """
    if not settings.service_enabled or not settings.service_channels:
        return
    built = {dispatcher.name for dispatcher in dispatchers}
    missing = [name for name in settings.service_channels if name not in built]
    if missing:
        raise CorrelatorStartupError(
            "OCC_SERVICE_CHANNELS names unconfigured channel(s): " + ", ".join(missing)
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
    publishers: Sequence[BasePublisher] | None = None,
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
    notice_outbox = outbox or AlertOutbox(store, active_dispatchers, settings, audit)
    notifier = ServiceNotifier(store, active_dispatchers, settings, audit, durable=True)
    _require_configured_service_channels(settings, active_dispatchers)
    # One registry for every listener: a canary is the same node whichever
    # transport delivered its event, and the silence check needs all of them.
    nodes = NodeRegistry(limit=settings.canary_registry_limit)
    stats = StatsReporter(store, audit, nodes=nodes)
    digest = DigestScheduler(store, notifier, settings, audit) if settings.digest_enabled else None
    # The window checks (`core.watch`): silence and the ingestion rate. The task
    # only exists when one of them can actually speak, so a correlator with the
    # service messages switched off pays nothing for it.
    window_checks = (
        settings.canary_silent_after > 0
        or settings.service_drops_threshold > 0
        or settings.service_rejections_threshold > 0
    )
    watch = HealthWatch(store, notifier, settings, audit) if window_checks else None
    # Cleanup is opt-in and never a readiness dependency: a janitor that cannot
    # run must not take the correlator out of the load balancer.
    retention = RetentionJanitor(store, settings, audit) if settings.retention_enabled else None
    repository = IncidentRepository(
        store,
        settings,
        audit,
        alert_channels=outbox.channels if outbox is not None else (),
    )
    # The budget rations notifications, so it needs the channels it summarises
    # through; with the budget off, `None` keeps the old behaviour exactly.
    budget = (
        AlertBudget(store, active_dispatchers, settings, audit, notifier=notifier)
        if settings.alert_budget_enabled
        else None
    )
    enricher = build_enricher(settings, store, audit, notifier)
    active_publishers = (
        list(publishers) if publishers is not None else build_publishers(settings, store, audit)
    )
    engine = CorrelationEngine(
        rules=build_rules(store, repository, settings, audit),
        dispatchers=active_dispatchers,
        dedup=DedupCache(store, ttl=settings.dedup_ttl, lease=settings.dedup_lease),
        settings=settings,
        audit=audit,
        enricher=enricher,
        outbox=outbox,
        notifier=notifier,
        budget=budget,
        publishers=active_publishers,
    )
    rate_limiter = build_rate_limiter(settings, store)
    receivers = build_receivers(settings, engine, audit, rate_limiter, nodes)
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
    started_publishers: list[BasePublisher] = []
    began = time.monotonic()
    scan_recovery: asyncio.Task[None] | None = None
    critical: list[asyncio.Task[None]] = []
    running = False
    draining = False

    def live() -> bool:
        return draining or not any(task.done() for task in critical)

    def ready() -> bool:
        return running and live() and all(receiver.is_running for receiver in receivers)

    if isinstance(health, HealthServer):
        health.set_runtime_checks(live, ready)

    async def supervise() -> None:
        while True:
            failed = next((task for task in critical if task.done()), None)
            listener_failed = not all(receiver.is_running for receiver in started)
            if isinstance(health, HealthServer):
                listener_failed = listener_failed or not health.is_running
            if failed is not None or listener_failed:
                name = failed.get_name() if failed is not None else "listener"
                error = None if failed is None or failed.cancelled() else failed.exception()
                audit.emit(
                    "critical_task_failed",
                    "error",
                    {
                        "task": name,
                        "error_type": type(error).__name__ if error else "unexpected_exit",
                    },
                )
                raise RuntimeError(f"critical runtime component stopped: {name}") from error
            await asyncio.sleep(0.05)

    supervisor: asyncio.Task[None] | None = None
    stop_waiter: asyncio.Task[bool] | None = None
    try:
        await log_handler.start()
        for receiver in receivers:
            started.append(receiver)
            await receiver.start()
        if health is not None:
            await health.start()
        for publisher in active_publishers:
            started_publishers.append(publisher)
            await publisher.start()
        await notice_outbox.start()
        scan_recovery = asyncio.create_task(engine.recover_scans(), name="scan-recovery")
        await stats.start()
        if digest is not None:
            await digest.start()
        if watch is not None:
            await watch.start()
        if budget is not None:
            await budget.start()
        if retention is not None:
            await retention.start()
        critical = [task for receiver in receivers for task in receiver.critical_tasks]
        critical.append(scan_recovery)
        critical.extend(
            task
            for component in (notice_outbox, stats, digest, watch, budget)
            if component is not None
            for task in component.critical_tasks
        )
        critical.extend(
            task for publisher in started_publishers for task in publisher.critical_tasks
        )
        running = True
        supervisor = asyncio.create_task(supervise(), name="runtime-supervisor")
        audit.emit(
            "startup",
            "info",
            {
                "receivers": [receiver.name for receiver in receivers],
                "rules": list(engine.rule_names),
                "channels": [dispatcher.name for dispatcher in active_dispatchers],
                "publishers": [publisher.name for publisher in started_publishers],
            },
        )
        await notifier.notify(
            ServiceKind.LIFECYCLE_STARTED,
            title="correlator started",
            lines=(
                f"Version {__version__}",
                f"Receivers: {', '.join(receiver.name for receiver in receivers)}",
                f"Channels: {', '.join(dispatcher.name for dispatcher in active_dispatchers)}",
            ),
            subject="started",
        )
        stop_waiter = asyncio.create_task(stop.wait(), name="runtime-stop")
        done, _ = await asyncio.wait((stop_waiter, supervisor), return_when=asyncio.FIRST_COMPLETED)
        if supervisor in done:
            await supervisor
    except Exception as exc:
        audit.emit(
            "runtime_failed" if running else "startup_failed",
            "error",
            {"error_type": type(exc).__name__},
        )
        raise
    finally:
        running = False
        draining = True
        if isinstance(health, HealthServer):
            health.draining = True
        for task in (supervisor, stop_waiter):
            if task is not None:
                task.cancel()
        await asyncio.gather(
            *(task for task in (supervisor, stop_waiter) if task is not None),
            return_exceptions=True,
        )
        # All cleanup operations are started, even if another raises or hangs.
        # Reserve half the single deadline for draining producers and half for
        # notice/client/pool closure. Cancellation remains cooperative asyncio.
        deadline = asyncio.get_running_loop().time() + settings.shutdown_timeout

        async def cleanup(
            name: str, operation: Callable[[], Awaitable[object]], budget: float
        ) -> None:
            try:
                async with asyncio.timeout(max(0.001, budget)):
                    await operation()
            except Exception as exc:
                audit.emit(
                    "cleanup_failed",
                    "error",
                    {
                        "resource": name,
                        "error_type": type(exc).__name__,
                    },
                )

        async def cancel_scan() -> None:
            if scan_recovery is not None:
                scan_recovery.cancel()
                await asyncio.gather(scan_recovery, return_exceptions=True)

        stops: list[tuple[str, Callable[[], Awaitable[object]]]] = [
            (receiver.name, receiver.stop) for receiver in reversed(started)
        ]
        stops.append(("scan-recovery", cancel_scan))
        stops.extend(
            (name, component.stop)
            for name, component in (
                ("outbox", notice_outbox),
                ("digest", digest),
                ("watch", watch),
                ("budget", budget),
                ("retention", retention),
                ("stats", stats),
            )
            if component is not None
        )
        stops.extend(
            (f"publisher:{publisher.name}", publisher.stop)
            for publisher in reversed(started_publishers)
        )
        await asyncio.gather(
            *(cleanup(name, operation, settings.shutdown_timeout / 2) for name, operation in stops)
        )
        # Even a broken stop implementation cannot orphan a supervised worker.
        for task in critical:
            task.cancel()
        await asyncio.gather(*critical, return_exceptions=True)

        def remaining() -> float:
            return max(0.001, deadline - asyncio.get_running_loop().time())

        await cleanup(
            "stop-notice",
            lambda: notifier.notify(
                ServiceKind.LIFECYCLE_STOPPED,
                title="correlator stopped",
                lines=(f"Version {__version__}", f"Uptime: {round(time.monotonic() - began, 1)} s"),
                subject="stopped",
            ),
            remaining() / 2,
        )
        await cleanup("stop-notice-attempt", notice_outbox.run_once, remaining() / 2)
        closes: list[tuple[str, Callable[[], Awaitable[object]]]] = [
            (dispatcher.target_id, dispatcher.aclose) for dispatcher in active_dispatchers
        ]
        if enricher is not None:
            closes.append(("enricher", enricher.aclose))
        closes.extend(
            (f"publisher:{publisher.name}", publisher.aclose) for publisher in started_publishers
        )
        if health is not None:
            closes.append(("health", health.stop))
        package_logger.removeHandler(log_handler)
        await asyncio.gather(
            *(cleanup(name, operation, remaining() / 2) for name, operation in closes)
        )
        await cleanup("log-handler", log_handler.stop, remaining() / 2)
        if owns_store:
            await cleanup("redis", store.aclose, remaining())
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

    if args.retention_run or args.dlq_list is not None or args.dlq_replay is not None:
        return asyncio.run(
            run_admin(
                settings,
                dlq_list=args.dlq_list,
                dlq_replay=args.dlq_replay,
                retention_run=args.retention_run,
            )
        )

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
