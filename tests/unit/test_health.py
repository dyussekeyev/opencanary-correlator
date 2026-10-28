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


def test_bound_port_before_start_raises(fake_redis: Any) -> None:
    """A caller that reads the port before binding gets a clear error, not None."""
    server = HealthServer(fake_redis, host="127.0.0.1", port=0)

    with pytest.raises(RuntimeError, match="not started"):
        _ = server.bound_port


async def test_start_is_idempotent(fake_redis: Any) -> None:
    """Starting twice must not bind a second listener on a different port."""
    server = await start_server(fake_redis)
    port = server.bound_port
    try:
        await server.start()
        assert server.bound_port == port
        assert (await http_get(port, "/healthz")).startswith(b"HTTP/1.1 200")
    finally:
        await server.stop()


async def test_an_empty_connection_does_not_take_the_listener_down(fake_redis: Any) -> None:
    """A TCP probe that connects and hangs up without a request line is normal."""
    server = await start_server(fake_redis)
    try:
        _reader, writer = await asyncio.open_connection("127.0.0.1", server.bound_port)
        writer.close()
        await writer.wait_closed()
        await asyncio.sleep(0.05)

        response = await http_get(server.bound_port, "/healthz")
    finally:
        await server.stop()

    assert response.startswith(b"HTTP/1.1 200")


async def test_a_rejected_peer_is_audited(audit: Any, audit_stream: Any, fake_redis: Any) -> None:
    """A 403 without an audit record leaves no trace of who probed the endpoint."""
    server = HealthServer(
        fake_redis,
        host="127.0.0.1",
        port=0,
        audit=audit,
        allowed_networks=parse_allowed_networks(["10.0.0.0/8"]),
    )
    await server.start()
    try:
        response = await http_get(server.bound_port, "/healthz")
    finally:
        await server.stop()

    assert response.startswith(b"HTTP/1.1 403")
    assert "health_request_rejected" in audit_stream.getvalue()


async def test_a_silent_probe_is_audited_as_a_timeout(
    monkeypatch: Any, audit: Any, audit_stream: Any, fake_redis: Any
) -> None:
    """A connection that never sends a request must be closed and recorded.

    Otherwise a slowloris on the probe port holds a task for the full timeout
    and an operator cannot tell a hung probe from a dead endpoint.
    """
    from opencanary_correlator import health

    monkeypatch.setattr(health, "_REQUEST_TIMEOUT", 0.05)
    server = HealthServer(fake_redis, host="127.0.0.1", port=0, audit=audit)
    await server.start()
    try:
        _reader, writer = await asyncio.open_connection("127.0.0.1", server.bound_port)
        await asyncio.sleep(0.3)
        writer.close()
        await writer.wait_closed()
    finally:
        await server.stop()

    assert "health_request_failed" in audit_stream.getvalue()
    assert "timeout" in audit_stream.getvalue()


async def test_connections_over_the_cap_are_refused(
    audit: Any, audit_stream: Any, fake_redis: Any
) -> None:
    """A peer that opens sockets it never finishes must not hold a task each.

    The listener binds every interface by default, so without a cap one peer can
    exhaust the process's descriptors and stall the probe it is supposed to
    answer.
    """
    server = HealthServer(
        fake_redis, host="127.0.0.1", port=0, audit=audit, max_concurrent_requests=1
    )
    await server.start()
    try:
        _idle_reader, idle_writer = await asyncio.open_connection("127.0.0.1", server.bound_port)
        await asyncio.sleep(0.1)  # the idle connection now holds the only slot
        response = await http_get(server.bound_port, "/healthz")
        idle_writer.close()
        await idle_writer.wait_closed()
    finally:
        await server.stop()

    assert response.startswith(b"HTTP/1.1 503")
    assert "too_many_requests" in audit_stream.getvalue()


async def test_a_header_block_beyond_the_byte_budget_is_still_answered(fake_redis: Any) -> None:
    """The drain loop stops at the budget instead of reading forever."""
    server = await start_server(fake_redis)
    try:
        _reader, writer = await asyncio.open_connection("127.0.0.1", server.bound_port)
        writer.write(b"GET /healthz HTTP/1.1\r\nX-Long: " + b"a" * 9000 + b"\r\n\r\n")
        await writer.drain()
        data = await asyncio.wait_for(_reader.read(), timeout=2)
        writer.close()
        await writer.wait_closed()
    finally:
        await server.stop()

    assert data.startswith(b"HTTP/1.1 200")
