"""Minimal HTTP health endpoint for load balancers and orchestrators."""

from __future__ import annotations

import asyncio
import json
from typing import Final

from opencanary_correlator.audit import AuditLogger
from opencanary_correlator.storage.redis_store import RedisStore

_REQUEST_TIMEOUT: Final[float] = 5.0
_MAX_REQUEST_BYTES: Final[int] = 8192

_OK_PATHS = frozenset({"/healthz", "/readyz", "/health"})


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
            path = parts[1] if len(parts) >= 2 else "/"
            consumed = len(request_line)
            while consumed < _MAX_REQUEST_BYTES:
                line = await asyncio.wait_for(reader.readline(), timeout=_REQUEST_TIMEOUT)
                consumed += len(line)
                if line in (b"\r\n", b"\n", b""):
                    break

            if path in _OK_PATHS:
                healthy = await self._store.ping()
                code = 200 if healthy else 503
                body = json.dumps({"status": "ok" if healthy else "degraded", "redis": healthy})
            elif path.startswith("/healthz") or path.startswith("/readyz"):
                code, body = 200, json.dumps({"status": "ok", "redis": None})
            else:
                code, body = 404, json.dumps({"error": "not found"})

            self._write(writer, code, body)
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
    def _write(writer: asyncio.StreamWriter, code: int, body: str) -> None:
        reason = {200: "OK", 404: "Not Found", 503: "Service Unavailable"}.get(code, "OK")
        payload = body.encode("utf-8")
        headers = (
            f"HTTP/1.1 {code} {reason}\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(payload)}\r\n"
            "Connection: close\r\n\r\n"
        )
        writer.write(headers.encode("latin-1") + payload)


__all__ = ["HealthServer"]
