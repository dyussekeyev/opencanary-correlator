"""Minimal HTTP health endpoint for load balancers and orchestrators."""

from __future__ import annotations

import asyncio
import json
from typing import Final
from urllib.parse import urlsplit

from opencanary_correlator import metrics
from opencanary_correlator.audit import AuditLogger
from opencanary_correlator.storage.redis_store import RedisStore

_REQUEST_TIMEOUT: Final[float] = 5.0
_MAX_REQUEST_BYTES: Final[int] = 8192

_OK_PATHS = frozenset({"/healthz", "/readyz", "/health"})
_METRICS_PATH: Final[str] = "/metrics"


class HealthServer:
    """Serve `/healthz` and `/readyz` with a Redis ping."""

    def __init__(
        self,
        store: RedisStore,
        *,
        host: str = "0.0.0.0",  # noqa: S104 - probes are served on every interface by default
        port: int = 8080,
        audit: AuditLogger | None = None,
    ) -> None:
        self._store = store
        self._host = host
        self._port = port
        self._audit = audit
        self._server: asyncio.AbstractServer | None = None
        self._bound_port: int | None = None

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
        self._server = await asyncio.start_server(self._handle_client, self._host, self._port)
        sockets = self._server.sockets or ()
        if sockets:
            self._bound_port = int(sockets[0].getsockname()[1])

    async def stop(self) -> None:
        """Close the listener."""
        server, self._server = self._server, None
        if server is not None:
            server.close()
            await server.wait_closed()

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            request_line = await asyncio.wait_for(reader.readline(), timeout=_REQUEST_TIMEOUT)
            if not request_line:
                return
            parts = request_line.decode("latin-1").split()
            target = parts[1] if len(parts) >= 2 else "/"
            try:
                path = urlsplit(target).path or "/"
            except ValueError:
                # Malformed absolute-form targets must not crash the probe listener.
                path = ""
            consumed = len(request_line)
            while consumed < _MAX_REQUEST_BYTES:
                line = await asyncio.wait_for(reader.readline(), timeout=_REQUEST_TIMEOUT)
                consumed += len(line)
                if line in (b"\r\n", b"\n", b""):
                    break

            if path == _METRICS_PATH:
                code = 200
                body = metrics.render().decode("utf-8")
                content_type = metrics.CONTENT_TYPE
            elif path in _OK_PATHS:
                healthy = await self._store.ping()
                code = 200 if healthy else 503
                body = json.dumps({"status": "ok" if healthy else "degraded", "redis": healthy})
                content_type = "application/json"
            else:
                code, body = 404, json.dumps({"error": "not found"})
                content_type = "application/json"

            self._write(writer, code, body, content_type)
            await writer.drain()
        except (TimeoutError, ConnectionError):
            if self._audit is not None:
                self._audit.emit("health_request_failed", "warning", {"reason": "timeout"})
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:  # pragma: no cover - peer already gone
                pass

    @staticmethod
    def _write(
        writer: asyncio.StreamWriter,
        code: int,
        body: str,
        content_type: str = "application/json",
    ) -> None:
        reason = {200: "OK", 404: "Not Found", 503: "Service Unavailable"}.get(code, "OK")
        payload = body.encode("utf-8")
        headers = (
            f"HTTP/1.1 {code} {reason}\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Content-Length: {len(payload)}\r\n"
            "Connection: close\r\n\r\n"
        )
        writer.write(headers.encode("latin-1") + payload)


__all__ = ["HealthServer"]
