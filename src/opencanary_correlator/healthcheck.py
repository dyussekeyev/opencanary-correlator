"""Docker health probe for the optional HTTP health endpoint.

The image uses this module instead of hard-coding the port, so changing or
disabling ``OCC_HEALTH_PORT`` keeps the container's health status meaningful.
``0`` or an empty value means the endpoint is disabled and the check succeeds.

The probe also follows ``OCC_HEALTH_HOST``: a listener bound to a wildcard is
dialled on the loopback address, a listener bound to ``::1`` is dialled there,
and any other configured address is used as-is. Without this the image would
report an unhealthy container as soon as the operator narrowed the binding.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable, Mapping
from http.client import HTTPConnection, HTTPException

DEFAULT_HEALTH_PORT = 15142
LOOPBACK_HOST = "127.0.0.1"
WILDCARD_HOSTS = frozenset({"0.0.0.0", "::", "[::]", "*"})  # noqa: S104 - compared, never bound
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


def parse_health_host(raw: str | None) -> str:
    """Return the address the probe should dial for a configured bind host."""
    if raw is None:
        return LOOPBACK_HOST
    host = raw.strip()
    if not host or host in WILDCARD_HOSTS:
        return LOOPBACK_HOST
    return host


def probe(host: str, port: int, *, timeout: float = PROBE_TIMEOUT_SECONDS) -> bool:
    """Return True when `/healthz` answers 200 on `host:port`."""
    connection = HTTPConnection(host, port, timeout=timeout)
    try:
        connection.request("GET", "/healthz")
        return bool(connection.getresponse().status == 200)
    except (OSError, HTTPException):
        return False
    finally:
        connection.close()


def main(
    environ: Mapping[str, str] | None = None,
    probe_fn: Callable[[str, int], bool] = probe,
) -> int:
    """Run the Docker health check and return a process exit code."""
    source = environ if environ is not None else os.environ
    raw = source.get("OCC_HEALTH_PORT")
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
    host = parse_health_host(source.get("OCC_HEALTH_HOST"))
    if probe_fn(host, port):
        return 0
    print(f"health probe failed on {host}:{port}", file=sys.stderr)
    return 1


if __name__ == "__main__":  # pragma: no cover - executed by Docker
    raise SystemExit(main())
