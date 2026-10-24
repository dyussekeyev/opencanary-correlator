"""Docker health probe for the optional HTTP health endpoint.

The image uses this module instead of hard-coding port 8080, so changing or
disabling ``OCC_HEALTH_PORT`` keeps the container's health status meaningful.
``0`` or an empty value means the endpoint is disabled and the check succeeds.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable, Mapping
from http.client import HTTPConnection, HTTPException

DEFAULT_HEALTH_PORT = 8080
PROBE_TIMEOUT_SECONDS = 3.0


def parse_health_port(raw: str) -> int | None:
    """Parse ``OCC_HEALTH_PORT``; return None when the endpoint is disabled."""
    value = raw.strip()
    if value in {"", "0"}:
        return None
    port = int(value)
    if not 1 <= port <= 65535:
        raise ValueError("health port must be between 1 and 65535")
    return port


def probe(port: int, *, timeout: float = PROBE_TIMEOUT_SECONDS) -> bool:
    """Return True when `/healthz` answers 200 on the loopback interface."""
    connection = HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        connection.request("GET", "/healthz")
        return bool(connection.getresponse().status == 200)
    except (OSError, HTTPException):
        return False
    finally:
        connection.close()


def main(
    environ: Mapping[str, str] | None = None,
    probe_fn: Callable[[int], bool] = probe,
) -> int:
    """Run the Docker health check and return a process exit code."""
    raw = (environ if environ is not None else os.environ).get("OCC_HEALTH_PORT")
    port: int | None
    if raw is None:
        port = DEFAULT_HEALTH_PORT
    else:
        try:
            port = parse_health_port(raw)
        except ValueError as exc:
            print(f"invalid OCC_HEALTH_PORT: {exc}", file=sys.stderr)
            return 1
    if port is None:
        return 0
    if probe_fn(port):
        return 0
    print(f"health probe failed on 127.0.0.1:{port}", file=sys.stderr)
    return 1


if __name__ == "__main__":  # pragma: no cover - executed by Docker
    raise SystemExit(main())
