"""End-to-end: SocketJSONHandler frames in, incidents and alerts out."""

from __future__ import annotations

import asyncio
import io
import json
import logging
import logging.handlers

import pytest

from opencanary_correlator.audit import AuditLogger
from opencanary_correlator.cli import run_correlator
from opencanary_correlator.connectors.base import BaseDispatcher, DispatchResult
from opencanary_correlator.constants import KEY_INCIDENTS
from opencanary_correlator.core.incident import Incident
from opencanary_correlator.health import HealthServer
from opencanary_correlator.storage.redis_store import RedisStore

pytestmark = pytest.mark.integration


class RecordingDispatcher(BaseDispatcher):
    """Collects delivered incidents."""

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


async def http_get(port: int, path: str) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(f"GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode())
    await writer.drain()
    data = await reader.read()
    writer.close()
    await writer.wait_closed()
    return data


async def test_health_endpoint_follows_the_runtime(
    fake_redis, settings_factory, free_tcp_port
) -> None:
    store = RedisStore(fake_redis)
    settings = settings_factory(
        tcp_port=free_tcp_port,
        syslog_enabled=False,
        health_port=None,
        rate_limit_events_per_minute=0,
    )
    health = HealthServer(store, host="127.0.0.1", port=0)
    stop_event = asyncio.Event()
    task = asyncio.create_task(
        run_correlator(
            settings,
            store=store,
            dispatchers=[],
            audit=AuditLogger("correlator", stream=io.StringIO()),
            stop_event=stop_event,
            health=health,
        )
    )
    try:
        for _ in range(150):
            try:
                port = health.bound_port
            except RuntimeError:
                await asyncio.sleep(0.02)
                continue
            break
        response = await http_get(port, "/healthz")
    finally:
        stop_event.set()
        await asyncio.wait_for(task, timeout=5)

    assert response.startswith(b"HTTP/1.1 200 OK")
    assert b'"redis": true' in response
    with pytest.raises((OSError, asyncio.TimeoutError)):
        await asyncio.wait_for(asyncio.open_connection("127.0.0.1", port), timeout=0.5)


async def test_full_stack_ingests_correlates_and_notifies(
    fake_redis, settings_factory, free_tcp_port, event_factory
) -> None:
    store = RedisStore(fake_redis)
    settings = settings_factory(
        tcp_port=free_tcp_port,
        syslog_enabled=False,
        health_port=None,
        rate_limit_events_per_minute=0,
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
    logger = logging.getLogger("tests.e2e.canary")
    logger.setLevel(logging.WARNING)
    logger.propagate = False
    try:
        await wait_for_port(free_tcp_port)
        handler = SocketJSONHandler("127.0.0.1", free_tcp_port)
        logger.handlers = [handler]
        try:
            logger.warning(json.dumps(event_factory(src_port=40001), sort_keys=True))
            logger.warning(json.dumps(event_factory(src_port=40002), sort_keys=True))
            logger.warning(json.dumps(event_factory(logtype=4002, dst_port=22), sort_keys=True))
        finally:
            logger.handlers = []
            handler.close()

        _reader, writer = await asyncio.open_connection("127.0.0.1", free_tcp_port)
        writer.write(b"[ERR] 'canary exploded'\n")
        await writer.drain()
        writer.close()
        await writer.wait_closed()

        for _ in range(200):
            if len(dispatcher.incidents) >= 2:
                break
            await asyncio.sleep(0.02)
    finally:
        stop_event.set()
        await asyncio.wait_for(task, timeout=5)

    keys = await store.zrangebyscore(KEY_INCIDENTS, "-inf", "+inf")
    assert len(keys) == 2

    ftp_keys = [key for key in keys if ":ftplogin:" in key]
    assert len(ftp_keys) == 1
    ftp_fields = await store.hgetall(ftp_keys[0])
    assert ftp_fields["events_count"] == "2"
    assert len(ftp_fields["events_list"].split(",")) == 2

    assert sorted(incident.INCIDENT_NAME for incident in dispatcher.incidents) == [
        "ftp.login_attempt",
        "ssh.login_attempt",
    ]

    records = [json.loads(line) for line in stream.getvalue().splitlines()]
    actions = [record["action"] for record in records]
    assert actions[0] == "receiver_started"
    assert {"startup", "event_rejected", "shutdown"} <= set(actions)
    assert actions[-1] == "shutdown"
    assert actions.count("alert_dispatch") == 2
    assert all(
        {"timestamp", "component", "action", "status", "details"} <= set(record)
        for record in records
    )


async def deliver_scan_events(
    *,
    store: RedisStore,
    settings,
    dispatcher: RecordingDispatcher,
    logger_name: str,
    payloads: list[dict[str, object]],
    timeout: float = 10.0,
) -> None:
    """Send SYN events over a real `SocketJSONHandler` socket and wait for alerts."""
    stop_event = asyncio.Event()
    task = asyncio.create_task(
        run_correlator(
            settings,
            store=store,
            dispatchers=[dispatcher],
            audit=AuditLogger("correlator", stream=io.StringIO()),
            stop_event=stop_event,
        )
    )
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.WARNING)
    logger.propagate = False
    try:
        await wait_for_port(settings.tcp_port)
        handler = SocketJSONHandler("127.0.0.1", settings.tcp_port)
        logger.handlers = [handler]
        try:
            for payload in payloads:
                logger.warning(json.dumps(payload, sort_keys=True))
        finally:
            logger.handlers = []
            handler.close()

        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while not dispatcher.incidents:
            if loop.time() >= deadline:
                raise AssertionError("no incident was delivered for the scan events")
            await asyncio.sleep(0.02)
    finally:
        stop_event.set()
        await asyncio.wait_for(task, timeout=10)


async def test_host_portscan_through_the_wire(
    fake_redis, settings_factory, free_tcp_port, event_factory
) -> None:
    """Five SYN packets to five ports of one canary produce one host-scan alert."""
    store = RedisStore(fake_redis)
    settings = settings_factory(
        tcp_port=free_tcp_port,
        syslog_enabled=False,
        health_port=None,
        rate_limit_events_per_minute=0,
    )
    dispatcher = RecordingDispatcher()
    payloads = [
        event_factory(
            logtype=5001,
            src_host="203.0.113.10",
            src_port=40000 + port,
            dst_host="10.0.0.2",
            dst_port=port,
            logdata={},
        )
        for port in (21, 22, 23, 24, 25)
    ]

    await deliver_scan_events(
        store=store,
        settings=settings,
        dispatcher=dispatcher,
        logger_name="tests.e2e.scan.host",
        payloads=payloads,
    )

    assert len(dispatcher.incidents) == 1
    incident = dispatcher.incidents[0]
    assert incident.INCIDENT_NAME == "scans.host_portscan"
    assert incident.logtype == 5003
    assert json.loads(incident.logdata or "[]") == [21, 22, 23, 24, 25]
    assert incident.events_count == 1

    keys = await store.zrangebyscore(KEY_INCIDENTS, "-inf", "+inf")
    assert len(keys) == 1
    assert keys[0].startswith("incident:hostportscan:203.0.113.10:")


async def test_network_portscan_through_the_wire(
    fake_redis, settings_factory, free_tcp_port, event_factory
) -> None:
    """The same source scanning two canaries on one port produces a network alert."""
    store = RedisStore(fake_redis)
    settings = settings_factory(
        tcp_port=free_tcp_port,
        syslog_enabled=False,
        health_port=None,
        rate_limit_events_per_minute=0,
    )
    dispatcher = RecordingDispatcher()
    payloads = [
        event_factory(
            logtype=5001,
            src_host="203.0.113.20",
            src_port=41000 + index,
            dst_host=dst_host,
            dst_port=22,
            reported_dst_host=reported_host,
            logdata={},
        )
        for index, (dst_host, reported_host) in enumerate(
            [("192.0.2.10", "127.0.0.1"), ("192.0.2.11", "127.0.0.2")]
        )
    ]

    await deliver_scan_events(
        store=store,
        settings=settings,
        dispatcher=dispatcher,
        logger_name="tests.e2e.scan.network",
        payloads=payloads,
    )

    assert len(dispatcher.incidents) == 1
    incident = dispatcher.incidents[0]
    assert incident.INCIDENT_NAME == "scans.network_portscan"
    assert incident.logtype == 5002
    assert json.loads(incident.logdata or "[]") == ["127.0.0.1", "127.0.0.2"]
    assert incident.dst_port == 22

    keys = await store.zrangebyscore(KEY_INCIDENTS, "-inf", "+inf")
    assert len(keys) == 1
    assert keys[0].startswith("incident:networkportscan:203.0.113.20:")
