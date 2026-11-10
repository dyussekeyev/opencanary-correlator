"""The process: lifecycle, signal handling, startup failures and exit codes."""

from __future__ import annotations

import asyncio
import io
import json
import logging
import logging.handlers
import signal
from typing import Any, cast

import pytest

from opencanary_correlator.app.parser import CorrelatorStartupError
from opencanary_correlator.app.runner import install_signal_handlers, main, run_correlator
from opencanary_correlator.audit import AuditLogger, RedisLogHandler
from opencanary_correlator.connectors.base import BaseDispatcher, DispatchResult, IncidentLike
from opencanary_correlator.constants import KEY_LOGS
from opencanary_correlator.core.incident import Incident
from opencanary_correlator.storage.redis_store import RedisStore


class RecordingDispatcher(BaseDispatcher):
    """Dispatcher collecting incidents in memory."""

    name = "recording"

    def __init__(self) -> None:
        self.incidents: list[Incident] = []

    async def dispatch(self, incident: IncidentLike) -> DispatchResult:
        assert isinstance(incident, Incident)
        self.incidents.append(incident)
        return DispatchResult(dispatcher=self.name, status="success")


class SocketJSONHandler(logging.handlers.SocketHandler):
    """Same framing as `opencanary.logger.SocketJSONHandler`."""

    def makePickle(self, record: logging.LogRecord) -> bytes:  # noqa: N802 - stdlib API
        return record.getMessage().encode("utf-8") + b"\n"


async def test_run_correlator_binds_health_to_the_configured_host(
    fake_redis: Any, settings_factory: Any, free_tcp_port: Any, monkeypatch: Any, audit: Any
) -> None:
    captured: dict[str, object] = {}

    class RecordingHealth:
        def __init__(
            self,
            store: Any,
            *,
            host: Any,
            port: Any,
            audit: Any = None,
            allowed_networks: Any = (),
        ) -> None:
            captured.update(host=host, port=port, allowed_networks=allowed_networks)

        async def start(self) -> None:
            return None

        async def stop(self) -> None:
            return None

    monkeypatch.setattr("opencanary_correlator.app.wiring.HealthServer", RecordingHealth)
    stop_event = asyncio.Event()
    stop_event.set()

    await run_correlator(
        settings_factory(
            tcp_port=free_tcp_port,
            syslog_enabled=False,
            health_host="127.0.0.1",
            health_port=8080,
            rate_limit_events_per_minute=0,
        ),
        store=RedisStore(fake_redis),
        dispatchers=[],
        audit=audit,
        stop_event=stop_event,
    )

    assert captured["host"] == "127.0.0.1"
    assert captured["port"] == 8080
    networks = captured["allowed_networks"]
    assert isinstance(networks, tuple)
    assert [str(net) for net in networks] == ["127.0.0.1/32", "::1/128"]


async def test_install_signal_handlers_registers_and_sets_stop_event() -> None:
    stop_event = asyncio.Event()
    previous_int = signal.getsignal(signal.SIGINT)
    previous_term = signal.getsignal(signal.SIGTERM)
    try:
        install_signal_handlers(stop_event)
        assert signal.getsignal(signal.SIGTERM) is not signal.SIG_DFL
        assert signal.getsignal(signal.SIGINT) is not signal.SIG_DFL
    finally:
        signal.signal(signal.SIGINT, previous_int)
        signal.signal(signal.SIGTERM, previous_term)


async def wait_for_port(port: int, timeout: float = 3.0) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        try:
            _reader, writer = await asyncio.open_connection("127.0.0.1", port)
        except OSError:
            if loop.time() >= deadline:
                raise
            await asyncio.sleep(0.02)
            continue
        writer.close()
        await writer.wait_closed()
        return


async def test_run_correlator_starts_and_stops_cleanly(
    fake_redis: Any,
    settings_factory: Any,
    free_tcp_port: Any,
    event_factory: Any,
    monkeypatch: Any,
) -> None:
    store = RedisStore(fake_redis)
    # `configure_logging` enables INFO by default, so the legacy journal carries
    # the lifecycle lines in production; pin the level instead of inheriting
    # whatever another test left on the root logger.
    monkeypatch.setattr(logging.getLogger("opencanary_correlator"), "level", logging.INFO)
    settings = settings_factory(
        tcp_port=free_tcp_port,
        syslog_enabled=False,
        health_port=None,
        rate_limit_events_per_minute=0,
        _env_file=None,
    )
    dispatcher = RecordingDispatcher()
    stream = io.StringIO()
    stop_event = asyncio.Event()
    task = asyncio.create_task(
        run_correlator(
            settings,
            store=store,
            dispatchers=[dispatcher],
            audit=AuditLogger("correlator", stream=stream),
            stop_event=stop_event,
        )
    )
    try:
        await wait_for_port(free_tcp_port)
        handler = SocketJSONHandler("127.0.0.1", free_tcp_port)
        logger = logging.getLogger("tests.cli.run")
        logger.handlers = [handler]
        logger.setLevel(logging.WARNING)
        logger.propagate = False
        try:
            logger.warning(json.dumps(event_factory(), sort_keys=True))
            for _ in range(100):
                if dispatcher.incidents:
                    break
                await asyncio.sleep(0.02)
        finally:
            logger.handlers = []
            handler.close()
        assert len(dispatcher.incidents) == 1
        logging.getLogger("opencanary_correlator.runtime").warning("console log line")
    finally:
        stop_event.set()
        await asyncio.wait_for(task, timeout=5)

    actions = [json.loads(line)["action"] for line in stream.getvalue().splitlines()]
    assert actions[0] == "receiver_started"
    assert "startup" in actions
    assert actions[-1] == "shutdown"
    journal = await store.lrange(KEY_LOGS)
    # Startup is journaled; the shutdown line is written after the journal
    # handler stops, so it only reaches stderr and the log file.
    lifecycle = [line for line in journal if line.startswith("startup complete:")]
    assert len(lifecycle) == 1
    assert lifecycle[0].startswith("startup complete: 1 receiver(s)")
    assert [line for line in journal if line not in lifecycle] == ["console log line"]
    assert not any(
        isinstance(handler, RedisLogHandler)
        for handler in logging.getLogger("opencanary_correlator").handlers
    )


async def test_lifecycle_reaches_the_operational_log(
    store: Any, settings_factory: Any, audit: Any, caplog: Any, free_tcp_port: Any
) -> None:
    """Startup and shutdown must be visible in the log, not only in the audit trail."""
    caplog.set_level(logging.INFO, logger="opencanary_correlator.app.runner")
    stop = asyncio.Event()
    stop.set()

    await run_correlator(
        settings_factory(tcp_port=free_tcp_port, syslog_enabled=False, health_port=None),
        store=store,
        dispatchers=[],
        audit=audit,
        stop_event=stop,
    )

    messages = [
        record.getMessage()
        for record in caplog.records
        if record.name == "opencanary_correlator.app.runner"
    ]
    started = next(index for index, text in enumerate(messages) if text.startswith("startup"))
    stopped = next(index for index, text in enumerate(messages) if text.startswith("shutdown"))
    assert messages[started].startswith("startup complete: 1 receiver(s)")
    assert messages[stopped].startswith("shutdown complete: 1 receiver(s)")
    assert started < stopped


async def test_critical_consumer_exit_stops_runtime(
    store: Any, settings_factory: Any, audit: Any, monkeypatch: Any, free_tcp_port: Any
) -> None:
    from opencanary_correlator.connectors.receivers._pipeline import EventPipeline

    async def exit_consumer(self: Any, queue: Any) -> None:
        return None

    monkeypatch.setattr(EventPipeline, "_consume", exit_consumer)
    with pytest.raises(RuntimeError, match="critical"):
        await asyncio.wait_for(
            run_correlator(
                settings_factory(tcp_port=free_tcp_port, syslog_enabled=False, health_port=None),
                store=store,
                dispatchers=[],
                audit=audit,
            ),
            2,
        )


async def test_cleanup_error_does_not_skip_other_resources(
    store: Any,
    settings_factory: Any,
    audit: Any,
    monkeypatch: Any,
    free_tcp_port: Any,
    caplog: Any,
) -> None:
    from opencanary_correlator.connectors.receivers.tcp_json import TCPJSONReceiver

    closed: list[str] = []
    original = TCPJSONReceiver.stop

    async def broken_stop(self: Any) -> None:
        await original(self)
        raise RuntimeError("cleanup failed")

    class Dispatcher(RecordingDispatcher):
        async def aclose(self) -> None:
            closed.append("dispatcher")

    monkeypatch.setattr(TCPJSONReceiver, "stop", broken_stop)
    stop = asyncio.Event()
    stop.set()
    await run_correlator(
        settings_factory(tcp_port=free_tcp_port, syslog_enabled=False, health_port=None),
        store=store,
        dispatchers=[Dispatcher()],
        audit=audit,
        stop_event=stop,
    )
    assert closed == ["dispatcher"]
    assert any(
        record.getMessage() == "cleanup failed for tcp_json: RuntimeError"
        for record in caplog.records
    )


async def test_stop_notice_precedes_client_close_and_is_not_start_suppressed(
    store: Any, settings_factory: Any, audit: Any
) -> None:
    calls: list[str] = []

    class Dispatcher(RecordingDispatcher):
        async def notify(self, message: Any) -> DispatchResult:
            calls.append(message.kind.value)
            return DispatchResult(dispatcher=self.name, status="success")

        async def aclose(self) -> None:
            calls.append("closed")

    stop = asyncio.Event()
    stop.set()
    await run_correlator(
        settings_factory(
            tcp_enabled=False,
            syslog_enabled=False,
            health_port=None,
            service_enabled=True,
            service_min_severity="info",
            service_categories=["lifecycle"],
        ),
        store=store,
        dispatchers=[Dispatcher()],
        audit=audit,
        stop_event=stop,
    )
    assert calls == ["lifecycle.started", "lifecycle.stopped", "closed"]


async def test_shutdown_budget_still_attempts_close_after_hung_stop(
    store: Any, settings_factory: Any, audit: Any, monkeypatch: Any
) -> None:
    from opencanary_correlator.core.stats import StatsReporter

    async def hung(self: Any) -> None:
        await asyncio.Event().wait()

    monkeypatch.setattr(StatsReporter, "stop", hung)
    closed: list[bool] = []

    class Dispatcher(RecordingDispatcher):
        async def aclose(self) -> None:
            closed.append(True)

    stop = asyncio.Event()
    stop.set()
    await asyncio.wait_for(
        run_correlator(
            settings_factory(
                tcp_enabled=False, syslog_enabled=False, health_port=None, shutdown_timeout=1
            ),
            store=store,
            dispatchers=[Dispatcher()],
            audit=audit,
            stop_event=stop,
        ),
        1.5,
    )
    assert closed == [True]
    # A failed plugin stop cannot leave its known worker running.
    assert not any(task.get_name() == "stats-heartbeat" for task in asyncio.all_tasks())


class UnreachableStore:
    """Redis stand-in whose server is down.

    Only the two methods the startup path reaches before giving up exist here, so
    the test also fails if a later refactor starts doing Redis work before the
    health check.
    """

    def __init__(self) -> None:
        self.closed = False

    async def ping(self) -> bool:
        return False

    async def aclose(self) -> None:
        self.closed = True


class ExplodingHealth:
    """Health server that refuses to start, to exercise the startup failure path."""

    async def start(self) -> None:
        raise RuntimeError("health listener failed")

    async def stop(self) -> None:
        return None


async def test_run_correlator_fails_fast_when_redis_is_down(
    settings_factory: Any, audit: Any, audit_stream: Any
) -> None:
    store = UnreachableStore()

    with pytest.raises(CorrelatorStartupError, match="Redis is not reachable"):
        await run_correlator(
            settings_factory(health_port=None),
            store=cast(Any, store),
            dispatchers=[],
            audit=audit,
        )

    records = [json.loads(line) for line in audit_stream.getvalue().splitlines()]
    assert [(record["action"], record["status"]) for record in records] == [
        ("startup_failed", "error")
    ]
    assert records[0]["details"]["reason"] == "redis_unavailable"
    # The caller supplied the store, so run_correlator must not close it behind
    # its back; only the store it opened itself is released (next test).
    assert store.closed is False


def test_main_reports_an_unreachable_redis_and_exits_1(monkeypatch: Any, capsys: Any) -> None:
    """The documented behaviour: one startup_failed line, one message, exit 1."""
    monkeypatch.delenv("OCC_REDIS_URL", raising=False)
    store = UnreachableStore()
    monkeypatch.setattr(RedisStore, "from_url", lambda *args, **kwargs: store)

    code = main(["--redis-url", "redis://127.0.0.1:6390/0"])

    captured = capsys.readouterr()
    assert code == 1
    assert "cannot start: Redis is not reachable" in captured.err
    lines = [json.loads(line) for line in captured.out.splitlines() if line.strip()]
    assert lines[-1]["action"] == "startup_failed"
    assert lines[-1]["details"]["reason"] == "redis_unavailable"
    # run_correlator opened this store itself, so it closes it on the way out.
    assert store.closed is True


def test_a_startup_failure_reaches_the_log_file(monkeypatch: Any, tmp_path: Any) -> None:
    monkeypatch.delenv("OCC_REDIS_URL", raising=False)
    store = UnreachableStore()
    monkeypatch.setattr(RedisStore, "from_url", lambda *args, **kwargs: store)
    target = tmp_path / "correlator.log"

    code = main(["--redis-url", "redis://127.0.0.1:6390/0", "--log-file", str(target)])

    assert code == 1
    text = target.read_text(encoding="utf-8")
    assert "CRITICAL" in text
    assert "cannot start: Redis is not reachable" in text


def test_an_unhandled_error_is_logged_with_a_traceback(monkeypatch: Any, tmp_path: Any) -> None:
    async def boom(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("correlator exploded")

    monkeypatch.setenv("OCC_REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setattr("opencanary_correlator.app.runner.run_correlator", boom)
    target = tmp_path / "correlator.log"

    code = main(["--log-file", str(target)])

    assert code == 1
    text = target.read_text(encoding="utf-8")
    assert "correlator stopped on an unhandled error" in text
    assert "RuntimeError: correlator exploded" in text


async def test_a_failure_during_startup_is_audited_with_its_type(
    store: Any, settings_factory: Any, audit: Any, audit_stream: Any
) -> None:
    settings = settings_factory(
        health_port=None,
        tcp_enabled=False,
        syslog_enabled=False,
        rate_limit_events_per_minute=0,
    )

    with pytest.raises(RuntimeError, match="health listener failed"):
        await run_correlator(
            settings,
            store=store,
            dispatchers=[],
            audit=audit,
            health=cast(Any, ExplodingHealth()),
        )

    records = [json.loads(line) for line in audit_stream.getvalue().splitlines()]
    failures = [record for record in records if record["action"] == "startup_failed"]
    assert len(failures) == 1
    assert failures[0]["status"] == "error"
    assert failures[0]["details"]["error_type"] == "RuntimeError"
    # The finally block still runs, so the shutdown record follows the failure.
    assert records[-1]["action"] == "shutdown"


def test_log_file_flag_writes_the_operational_log(monkeypatch: Any, tmp_path: Any) -> None:
    monkeypatch.setenv("OCC_REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.delenv("OCC_LOG_FILE", raising=False)
    target = tmp_path / "logs" / "correlator.log"

    code = main(["--check-config", "--log-file", str(target)])
    logging.getLogger("opencanary_correlator.test").warning("probe record")

    assert code == 0
    assert "probe record" in target.read_text(encoding="utf-8")


def test_an_unwritable_log_file_stops_startup(monkeypatch: Any, capsys: Any, tmp_path: Any) -> None:
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory", encoding="utf-8")
    monkeypatch.setenv("OCC_REDIS_URL", "redis://localhost:6379/0")

    code = main(["--check-config", "--log-file", str(blocker / "correlator.log")])

    assert code == 2
    assert "cannot open the log file" in capsys.readouterr().err
