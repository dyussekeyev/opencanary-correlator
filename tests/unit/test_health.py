"""HTTP health endpoint tests."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from opencanary_correlator import metrics
from opencanary_correlator.config import DEFAULT_HEALTH_HOST, DEFAULT_HEALTH_PORT
from opencanary_correlator.connectors.receivers._allowlist import parse_allowed_networks
from opencanary_correlator.health import HealthServer
from opencanary_correlator.storage.redis_store import RedisStore


class DeadStore:
    """Store stand-in whose Redis is unreachable."""

    async def ping(self) -> bool:
        return False


async def http_get(port: int, path: str) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(f"GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode())
    await writer.drain()
    data = await reader.read()
    writer.close()
    await writer.wait_closed()
    return data


async def start_server(store: Any) -> HealthServer:
    server = HealthServer(store, host="127.0.0.1", port=0)
    await server.start()
    return server


class DummyListener:
    """Stand-in for the server object `asyncio.start_server` returns."""

    sockets: tuple[object, ...] = ()

    def close(self) -> None:
        return None

    async def wait_closed(self) -> None:
        return None


async def test_health_server_defaults_to_all_interfaces(monkeypatch: Any, fake_redis: Any) -> None:
    captured: dict[str, object] = {}

    async def fake_start_server(
        handler: Any, host: str | None = None, port: int | None = None
    ) -> DummyListener:
        captured.update(host=host, port=port)
        return DummyListener()

    monkeypatch.setattr("opencanary_correlator.health.asyncio.start_server", fake_start_server)
    server = HealthServer(RedisStore(fake_redis))

    await server.start()

    assert captured == {"host": DEFAULT_HEALTH_HOST, "port": DEFAULT_HEALTH_PORT}


async def test_health_server_binds_the_configured_host(monkeypatch: Any, fake_redis: Any) -> None:
    captured: dict[str, object] = {}

    async def fake_start_server(
        handler: Any, host: str | None = None, port: int | None = None
    ) -> DummyListener:
        captured.update(host=host, port=port)
        return DummyListener()

    monkeypatch.setattr("opencanary_correlator.health.asyncio.start_server", fake_start_server)
    server = HealthServer(RedisStore(fake_redis), host="127.0.0.1", port=9090)

    await server.start()

    assert captured == {"host": "127.0.0.1", "port": 9090}


async def test_healthz_reports_redis_ok(fake_redis: Any) -> None:
    server = await start_server(RedisStore(fake_redis))
    try:
        response = await http_get(server.bound_port, "/healthz")
    finally:
        await server.stop()

    assert response.startswith(b"HTTP/1.1 200 OK")
    assert b'"redis": true' in response


async def test_readyz_reports_degraded_when_redis_is_down() -> None:
    server = await start_server(DeadStore())
    try:
        response = await http_get(server.bound_port, "/readyz")
    finally:
        await server.stop()

    assert response.startswith(b"HTTP/1.1 503 Service Unavailable")
    assert b'"status": "degraded"' in response


async def test_metrics_endpoint_serves_prometheus_text_without_redis() -> None:
    server = await start_server(DeadStore())
    try:
        response = await http_get(server.bound_port, "/metrics")
    finally:
        await server.stop()

    assert response.startswith(b"HTTP/1.1 200 OK")
    assert b"Content-Type: text/plain; version=0.0.4; charset=utf-8" in response
    assert b"opencanary_events_total" in response
    assert b"opencanary_build_info" in response
    assert b'"status"' not in response.split(b"\r\n\r\n", 1)[1]


async def test_metrics_endpoint_exports_live_counters() -> None:
    metrics.EVENTS_TOTAL.labels(result="test_health_endpoint").inc()
    server = await start_server(DeadStore())
    try:
        response = await http_get(server.bound_port, "/metrics")
    finally:
        await server.stop()

    assert b'opencanary_events_total{result="test_health_endpoint"} 1.0' in response


async def test_metrics_query_string_is_served() -> None:
    server = await start_server(DeadStore())
    try:
        response = await http_get(server.bound_port, "/metrics?format=prometheus")
    finally:
        await server.stop()

    assert response.startswith(b"HTTP/1.1 200 OK")
    assert b"opencanary_events_total" in response


async def test_unknown_path_returns_404(fake_redis: Any) -> None:
    server = await start_server(RedisStore(fake_redis))
    try:
        response = await http_get(server.bound_port, "/unknown")
    finally:
        await server.stop()

    assert response.startswith(b"HTTP/1.1 404 Not Found")


@pytest.mark.parametrize("path", ["/healthz?x=1", "/readyz?verbose"])
async def test_query_string_still_pings_redis(path: str) -> None:
    server = await start_server(DeadStore())
    try:
        response = await http_get(server.bound_port, path)
    finally:
        await server.stop()

    assert response.startswith(b"HTTP/1.1 503 Service Unavailable")
    assert b'"status": "degraded"' in response


async def test_query_string_keeps_healthy_response(fake_redis: Any) -> None:
    server = await start_server(RedisStore(fake_redis))
    try:
        response = await http_get(server.bound_port, "/healthz?x=1")
    finally:
        await server.stop()

    assert response.startswith(b"HTTP/1.1 200 OK")
    assert b'"redis": true' in response


@pytest.mark.parametrize(
    "path", ["/healthzfoo", "/readyzbar", "/healthz/", "/metricsfoo", "/metrics/"]
)
async def test_path_prefix_is_not_a_health_endpoint(path: str, fake_redis: Any) -> None:
    server = await start_server(RedisStore(fake_redis))
    try:
        response = await http_get(server.bound_port, path)
    finally:
        await server.stop()

    assert response.startswith(b"HTTP/1.1 404 Not Found")


async def test_malformed_absolute_target_returns_404(fake_redis: Any) -> None:
    server = await start_server(RedisStore(fake_redis))
    try:
        response = await http_get(server.bound_port, "http://[::1")
    finally:
        await server.stop()

    assert response.startswith(b"HTTP/1.1 404 Not Found")


async def test_stop_is_idempotent(fake_redis: Any) -> None:
    server = await start_server(RedisStore(fake_redis))
    await server.stop()
    await server.stop()


@pytest.mark.parametrize(
    ("networks", "expected"),
    [
        (("127.0.0.1/32",), b"HTTP/1.1 200 OK"),
        (("::1/128",), b"HTTP/1.1 403 Forbidden"),
        (("10.0.0.0/8",), b"HTTP/1.1 403 Forbidden"),
    ],
)
async def test_health_allowlist_gates_metrics_and_probes(
    networks: tuple[str, ...], expected: bytes, fake_redis: Any
) -> None:
    server = HealthServer(
        RedisStore(fake_redis),
        host="127.0.0.1",
        port=0,
        allowed_networks=parse_allowed_networks(networks),
    )
    await server.start()
    try:
        metrics_response = await http_get(server.bound_port, "/metrics")
        probe_response = await http_get(server.bound_port, "/healthz")
    finally:
        await server.stop()

    assert metrics_response.startswith(expected)
    assert probe_response.startswith(expected)
    if expected.endswith(b"Forbidden"):
        for response in (metrics_response, probe_response):
            assert response.endswith(b'{"error": "forbidden"}')
