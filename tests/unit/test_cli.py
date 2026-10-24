"""CLI wiring: configuration validation, redaction, dispatchers and lifecycle."""

from __future__ import annotations

import asyncio
import io
import json
import logging
import logging.handlers
import signal

from opencanary_correlator.audit import AuditLogger, RedisLogHandler
from opencanary_correlator.cli import (
    build_dispatchers,
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
