"""Minimal HTTP health endpoint for load balancers and orchestrators."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from typing import Final
from urllib.parse import urlsplit

from opencanary_correlator import metrics
from opencanary_correlator.audit import AuditLogger
from opencanary_correlator.config_validation import DEFAULT_HEALTH_HOST, DEFAULT_HEALTH_PORT
from opencanary_correlator.connectors.receivers._allowlist import (
    AllowedNetworks,
    is_peer_allowed,
)
from opencanary_correlator.storage.redis_store import RedisStore

_REQUEST_TIMEOUT: Final[float] = 5.0
_MAX_REQUEST_BYTES: Final[int] = 8192

#: Concurrent connections the probe listener serves.
#:
#: The listener binds every interface by default and is unauthenticated, and
#: every accepted socket costs a task until its request completes. Without a
#: cap a single peer opening sockets it never finishes exhausts file descriptors
#: and stalls `/healthz` for the orchestrator as well — the probe that is
#: supposed to report an unhealthy process would hang instead. A real probe uses
#: one connection at a time, so the cap is far above any honest traffic.
_MAX_CONCURRENT_REQUESTS: Final[int] = 128

_OK_PATHS = frozenset({"/healthz", "/readyz", "/health"})
_METRICS_PATH: Final[str] = "/metrics"


class HealthServer:
    """Serve process liveness and dependency/runtime readiness with bounded HTTP."""

    def __init__(
        self,
        store: RedisStore,
        *,
        host: str = DEFAULT_HEALTH_HOST,
        port: int = DEFAULT_HEALTH_PORT,
        audit: AuditLogger | None = None,
        allowed_networks: AllowedNetworks = (),
        max_concurrent_requests: int = _MAX_CONCURRENT_REQUESTS,
    ) -> None:
        self._store = store
        self._host = host
        self._port = port
        self._audit = audit
        # Peers outside these networks get a 403 before any state is read.
        self._allowed_networks = allowed_networks
        self._max_concurrent_requests = max(1, max_concurrent_requests)
        self._active_requests = 0
        self._server: asyncio.AbstractServer | None = None
        self._bound_port: int | None = None
        self.draining = False
        self._live: Callable[[], bool] = lambda: True
        self._ready: Callable[[], bool] = lambda: True
        self._clients: set[asyncio.Task[None]] = set()

    def set_runtime_checks(self, live: Callable[[], bool], ready: Callable[[], bool]) -> None:
        """Attach local task/listener checks; no external provider controls liveness."""
        self._live, self._ready = live, ready

    @property
    def is_running(self) -> bool:
        """Whether the probe listener is serving."""
        return self._server is not None and self._server.is_serving()

    @property
    def bound_port(self) -> int:
        """Actual listening port."""
        if self._bound_port is None:
            raise RuntimeError("health server is not started")
        return self._bound_port

    async def start(self) -> None:
        """Bind the HTTP listener."""
        if self._server is not None:
            return
        self._server = await asyncio.start_server(
            self._accept_client, self._host, self._port, limit=_MAX_REQUEST_BYTES
        )
        sockets = self._server.sockets or ()
        if sockets:
            self._bound_port = int(sockets[0].getsockname()[1])

    async def stop(self) -> None:
        """Close the listener."""
        server, self._server = self._server, None
        if server is not None:
            server.close()
        # Cancel first: `wait_closed()` waits for connection handlers, and a
        # silent probe would otherwise hold shutdown for `_REQUEST_TIMEOUT`.
        clients = tuple(self._clients)
        for task in clients:
            task.cancel()
        await asyncio.gather(*clients, return_exceptions=True)
        if server is not None:
            await server.wait_closed()

    def _accept_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        # Reserve synchronously, before scheduling: over-cap sockets get no reader
        # or refusal task. A reset under overload is preferable to unbounded tasks.
        if self._active_requests >= self._max_concurrent_requests:
            self._reject_overloaded(writer)
            writer.close()
            return
        self._active_requests += 1
        task = asyncio.create_task(self._handle_client(reader, writer), name="health-request")
        self._clients.add(task)
        task.add_done_callback(self._clients.discard)

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            async with asyncio.timeout(_REQUEST_TIMEOUT):
                await self._serve_request(reader, writer)
        except (TimeoutError, ConnectionError):
            if self._audit is not None:
                self._audit.emit(
                    "health_request_failed", "warning", {"reason": "timeout_or_disconnect"}
                )
        except ValueError:
            self._write(writer, 431, json.dumps({"error": "headers too large"}))
            if self._audit is not None:
                self._audit.emit(
                    "health_request_rejected", "warning", {"reason": "request_too_large"}
                )
        finally:
            self._active_requests -= 1
            writer.close()
            # Do not let a peer extend the total deadline through wait_closed.

    async def _serve_request(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        request_line = await reader.readline()
        if not request_line:
            return
        # Drain the headers before answering, even for rejected peers: closing
        # with unread request bytes makes the kernel reset the connection, so
        # the client never sees the 403.
        consumed = len(request_line)
        while consumed < _MAX_REQUEST_BYTES:
            line = await reader.readline()
            consumed += len(line)
            if consumed > _MAX_REQUEST_BYTES:
                raise ValueError("request too large")
            if line in (b"\r\n", b"\n", b""):
                break
        else:
            raise ValueError("request too large")

        if not self._peer_allowed(writer):
            self._write(writer, 403, json.dumps({"error": "forbidden"}))
            await writer.drain()
            if self._audit is not None:
                self._audit.emit(
                    "health_request_rejected", "warning", {"reason": "peer_not_allowed"}
                )
            return

        parts = request_line.decode("latin-1").split()
        target = parts[1] if len(parts) >= 2 else "/"
        try:
            path = urlsplit(target).path or "/"
        except ValueError:
            # Malformed absolute-form targets must not crash the probe listener.
            path = ""

        if path == _METRICS_PATH:
            code = 200
            body = metrics.render().decode("utf-8")
            content_type = metrics.CONTENT_TYPE
        elif path in _OK_PATHS:
            if path == "/healthz":
                healthy = self._live()
                details: dict[str, object] = {"live": healthy}
            else:
                redis = await self._store.ping()
                healthy = redis and self._live() and self._ready() and not self.draining
                details = {"redis": redis, "draining": self.draining}
            code = 200 if healthy else 503
            body = json.dumps({"status": "ok" if healthy else "degraded", **details})
            content_type = "application/json"
        else:
            code, body = 404, json.dumps({"error": "not found"})
            content_type = "application/json"

        self._write(writer, code, body, content_type)
        await writer.drain()

    def _reject_overloaded(self, writer: asyncio.StreamWriter) -> None:
        """Answer a connection over the cap with a 503 and audit the refusal."""
        self._write(writer, 503, json.dumps({"error": "busy"}))
        if self._audit is not None:
            self._audit.emit(
                "health_request_rejected",
                "warning",
                {"reason": "too_many_requests", "active": self._active_requests},
            )

    def _peer_allowed(self, writer: asyncio.StreamWriter) -> bool:
        if not self._allowed_networks:
            return True
        peername = writer.get_extra_info("peername")
        peer_ip = str(peername[0]) if peername else ""
        return is_peer_allowed(peer_ip, self._allowed_networks)

    @staticmethod
    def _write(
        writer: asyncio.StreamWriter,
        code: int,
        body: str,
        content_type: str = "application/json",
    ) -> None:
        reason = {
            200: "OK",
            403: "Forbidden",
            404: "Not Found",
            431: "Request Header Fields Too Large",
            503: "Service Unavailable",
        }.get(code, "OK")
        payload = body.encode("utf-8")
        headers = (
            f"HTTP/1.1 {code} {reason}\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Content-Length: {len(payload)}\r\n"
            "Connection: close\r\n\r\n"
        )
        writer.write(headers.encode("latin-1") + payload)


__all__ = ["HealthServer"]
