"""CLI wiring: configuration validation, redaction, dispatchers and lifecycle."""

from __future__ import annotations

import asyncio
import io
import json
import logging
import logging.handlers
import signal

import pytest

from opencanary_correlator.audit import AuditLogger, RedisLogHandler
from opencanary_correlator.cli import (
    CorrelatorStartupError,
    build_dispatchers,
    build_receivers,
    channel_names,
    install_signal_handlers,
    main,
    run_correlator,
    safe_redis_url,
)
from opencanary_correlator.connectors.base import BaseDispatcher, DispatchResult
from opencanary_correlator.constants import KEY_LOGS
from opencanary_correlator.core.incident import Incident
from opencanary_correlator.storage.redis_store import RedisStore


class RecordingDispatcher(BaseDispatcher):
    """Dispatcher collecting incidents in memory."""

    name = "recording"

    def __init__(self) -> None:
        self.incidents: list[Incident] = []

    async def dispatch(self, incident: Incident) -> DispatchResult:
        self.incidents.append(incident)
        return DispatchResult(dispatcher=self.name, status="success")


class SocketJSONHandler(logging.handlers.SocketHandler):
    """Same framing as `opencanary.logger.SocketJSONHandler`."""

    def makePickle(self, record: logging.LogRecord) -> bytes:  # noqa: N802 - stdlib API
        return record.getMessage().encode("utf-8") + b"\n"


def test_safe_redis_url_masks_the_password() -> None:
    masked = safe_redis_url("redis://user:supersecret@redis.example:6380/1")

    assert "supersecret" not in masked
    assert masked == "redis://user:***@redis.example:6380/1"


def test_check_config_prints_redacted_summary(monkeypatch, capsys) -> None:
    monkeypatch.setenv("OCC_REDIS_URL", "redis://user:supersecret@redis.example:6379/0")
    monkeypatch.setenv("OCC_SLACK_WEBHOOKS", "https://hooks.slack.test/x")

    code = main(["--check-config"])

    captured = capsys.readouterr()
    assert code == 0
    assert "supersecret" not in captured.out
    assert "***" in captured.out
    payload = json.loads(captured.out)
    assert payload["channels"] == ["slack"]


def test_check_config_accepts_env_health_port_zero(monkeypatch, capsys) -> None:
    monkeypatch.setenv("OCC_REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setenv("OCC_HEALTH_PORT", "0")

    code = main(["--check-config"])

    captured = capsys.readouterr()
    assert code == 0, captured.err
    assert json.loads(captured.out)["health_port"] is None


def test_check_config_cli_health_port_zero_overrides_the_env(monkeypatch, capsys) -> None:
    monkeypatch.setenv("OCC_REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setenv("OCC_HEALTH_PORT", "9090")

    code = main(["--check-config", "--health-port", "0"])

    captured = capsys.readouterr()
    assert code == 0, captured.err
    assert json.loads(captured.out)["health_port"] is None


def test_check_config_reports_the_configured_health_host(monkeypatch, capsys) -> None:
    monkeypatch.setenv("OCC_REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setenv("OCC_HEALTH_HOST", "127.0.0.1")

    code = main(["--check-config"])

    captured = capsys.readouterr()
    assert code == 0, captured.err
    assert json.loads(captured.out)["health_host"] == "127.0.0.1"


async def test_run_correlator_binds_health_to_the_configured_host(
    fake_redis, settings_factory, free_tcp_port, monkeypatch, audit
) -> None:
    captured: dict[str, object] = {}

    class RecordingHealth:
        def __init__(self, store, *, host, port, audit=None) -> None:
            captured.update(host=host, port=port)

        async def start(self) -> None:
            return None

        async def stop(self) -> None:
            return None

    monkeypatch.setattr("opencanary_correlator.cli.HealthServer", RecordingHealth)
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

    assert captured == {"host": "127.0.0.1", "port": 8080}


def test_check_config_rejects_invalid_override(monkeypatch, capsys) -> None:
    monkeypatch.setenv("OCC_REDIS_URL", "redis://localhost:6379/0")

    code = main(["--check-config", "--redis-url", "http://localhost:6379/0"])

    assert code == 2
    assert "redis_url" in capsys.readouterr().err


def test_check_config_without_redis_url_fails(monkeypatch, capsys) -> None:
    monkeypatch.delenv("OCC_REDIS_URL", raising=False)

    code = main(["--check-config"])

    assert code == 2
    assert "redis_url" in capsys.readouterr().err


async def test_build_dispatchers_follows_settings(settings_factory, store) -> None:
    settings = settings_factory(
        webhook_urls=["https://siem.test/hook"],
        slack_webhooks=["https://hooks.slack.test/x"],
        discord_webhooks=["https://discord.test/webhook"],
        telegram_token="1:token",
        telegram_chat_ids=["1", "2"],
        smtp_host="smtp.test",
        smtp_to=["soc@example.test"],
    )

    dispatchers = build_dispatchers(settings, store)
    try:
        assert [dispatcher.name for dispatcher in dispatchers] == [
            "webhook",
            "slack",
            "discord",
            "telegram",
            "telegram",
            "smtp",
        ]
    finally:
        await asyncio.gather(*(dispatcher.aclose() for dispatcher in dispatchers))


async def test_build_dispatchers_respects_disabled_channels(settings_factory, store) -> None:
    settings = settings_factory(
        slack_enabled=False,
        slack_webhooks=["https://hooks.slack.test/x"],
        smtp_enabled=False,
        smtp_host="smtp.test",
        smtp_to=["soc@example.test"],
    )

    assert build_dispatchers(settings, store) == []
    assert channel_names(settings) == []


async def test_build_dispatchers_passes_implicit_tls_to_smtp(
    settings_factory, store, monkeypatch
) -> None:
    captured: dict = {}

    class RecordingSmtp:
        def __init__(self, **kwargs) -> None:
            captured.update(kwargs)

    monkeypatch.setattr("opencanary_correlator.cli.SmtpDispatcher", RecordingSmtp)
    settings = settings_factory(
        smtp_host="smtp.test",
        smtp_to=["soc@example.test"],
        smtp_starttls=False,
        smtp_use_tls=True,
    )

    dispatchers = build_dispatchers(settings, store)

    assert len(dispatchers) == 1
    assert captured["start_tls"] is False
    assert captured["use_tls"] is True


async def test_build_dispatchers_scopes_breakers_to_each_endpoint(
    settings_factory, store, monkeypatch
) -> None:
    names: list[str] = []

    class RecordingBreaker:
        def __init__(self, _store, name: str) -> None:
            names.append(name)

    monkeypatch.setattr("opencanary_correlator.cli.CircuitBreaker", RecordingBreaker)
    settings = settings_factory(
        webhook_urls=["https://siem.test/a", "https://siem.test/b"],
        slack_webhooks=["https://slack.test/a", "https://slack.test/b"],
        discord_webhooks=["https://discord.test/a", "https://discord.test/b"],
        telegram_token="1:token",
        telegram_chat_ids=["1", "2"],
    )

    dispatchers = build_dispatchers(settings, store)
    try:
        assert [name.split(":", 1)[0] for name in names] == [
            "webhook",
            "webhook",
            "slack",
            "slack",
            "discord",
            "discord",
            "telegram",
            "telegram",
        ]
        assert len(set(names)) == len(names)
        assert not any(
            marker in name
            for name in names
            for marker in ("siem.test", "slack.test", "discord.test")
        )
    finally:
        await asyncio.gather(*(dispatcher.aclose() for dispatcher in dispatchers))


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
    fake_redis, settings_factory, free_tcp_port, event_factory
) -> None:
    store = RedisStore(fake_redis)
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
    assert await store.lrange(KEY_LOGS) == ["console log line"]
    assert not any(
        isinstance(handler, RedisLogHandler)
        for handler in logging.getLogger("opencanary_correlator").handlers
    )


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
    settings_factory, audit, audit_stream
) -> None:
    store = UnreachableStore()

    with pytest.raises(CorrelatorStartupError, match="Redis is not reachable"):
        await run_correlator(
            settings_factory(health_port=None), store=store, dispatchers=[], audit=audit
        )

    records = [json.loads(line) for line in audit_stream.getvalue().splitlines()]
    assert [(record["action"], record["status"]) for record in records] == [
        ("startup_failed", "error")
    ]
    assert records[0]["details"]["reason"] == "redis_unavailable"
    # The caller supplied the store, so run_correlator must not close it behind
    # its back; only the store it opened itself is released (next test).
    assert store.closed is False


def test_main_reports_an_unreachable_redis_and_exits_1(monkeypatch, capsys) -> None:
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


def test_main_reports_a_missing_legacy_config(monkeypatch, capsys, tmp_path) -> None:
    monkeypatch.delenv("OCC_REDIS_URL", raising=False)
    missing = tmp_path / "absent.conf"

    code = main(["--config", str(missing)])

    captured = capsys.readouterr()
    assert code == 2
    assert "cannot load configuration" in captured.err
    assert "absent.conf" in captured.err


def test_main_reports_a_malformed_legacy_config(monkeypatch, capsys, tmp_path) -> None:
    monkeypatch.delenv("OCC_REDIS_URL", raising=False)
    broken = tmp_path / "broken.conf"
    broken.write_text("{not json", encoding="utf-8")

    code = main(["--config", str(broken)])

    captured = capsys.readouterr()
    assert code == 2
    assert "cannot load configuration" in captured.err


async def test_a_failure_during_startup_is_audited_with_its_type(
    store, settings_factory, audit, audit_stream
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
            health=ExplodingHealth(),
        )

    records = [json.loads(line) for line in audit_stream.getvalue().splitlines()]
    failures = [record for record in records if record["action"] == "startup_failed"]
    assert len(failures) == 1
    assert failures[0]["status"] == "error"
    assert failures[0]["details"]["error_type"] == "RuntimeError"
    # The finally block still runs, so the shutdown record follows the failure.
    assert records[-1]["action"] == "shutdown"


def test_redis_url_flag_alone_satisfies_the_required_setting(monkeypatch, capsys) -> None:
    """`--redis-url` exists to supply the required URL, so it must reach validation."""
    monkeypatch.delenv("OCC_REDIS_URL", raising=False)

    code = main(["--check-config", "--redis-url", "redis://127.0.0.1:6390/0"])

    captured = capsys.readouterr()
    assert code == 0, captured.err
    assert json.loads(captured.out)["redis_url"] == "redis://127.0.0.1:6390/0"


def test_log_level_flag_overrides_the_environment(monkeypatch, capsys) -> None:
    monkeypatch.setenv("OCC_REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setenv("OCC_LOG_LEVEL", "WARNING")

    code = main(["--check-config", "--log-level", "DEBUG"])

    assert code == 0
    assert json.loads(capsys.readouterr().out)["log_level"] == "DEBUG"


def test_channel_names_counts_every_telegram_chat(settings_factory) -> None:
    settings = settings_factory(
        telegram_token="123:abc",
        telegram_chat_ids=["-1001", "-1002"],
        smtp_enabled=True,
        smtp_host="smtp.example",
        smtp_to=["ops@example"],
    )

    assert channel_names(settings) == ["telegram", "telegram", "smtp"]


def test_channel_names_skips_smtp_without_a_recipient(settings_factory) -> None:
    settings = settings_factory(smtp_enabled=True, smtp_host="smtp.example", smtp_to=[])

    assert channel_names(settings) == []


def test_build_receivers_wires_every_enabled_listener(settings_factory, audit) -> None:
    settings = settings_factory(
        tcp_enabled=True,
        syslog_enabled=True,
        syslog_udp_enabled=True,
        rate_limit_events_per_minute=0,
    )

    receivers = build_receivers(settings, object(), audit, None)

    assert [receiver.name for receiver in receivers] == ["tcp_json", "syslog_tcp", "syslog_udp"]
    assert receivers[0].port == settings.tcp_port
    assert receivers[1].port == receivers[2].port == settings.syslog_port


def test_build_receivers_skips_disabled_listeners(settings_factory, audit) -> None:
    settings = settings_factory(tcp_enabled=False, syslog_enabled=False)

    assert build_receivers(settings, object(), audit, None) == []


def test_build_receivers_keeps_syslog_tcp_when_udp_is_disabled(settings_factory, audit) -> None:
    settings = settings_factory(tcp_enabled=False, syslog_enabled=True, syslog_udp_enabled=False)

    assert [receiver.name for receiver in build_receivers(settings, object(), audit, None)] == [
        "syslog_tcp"
    ]
