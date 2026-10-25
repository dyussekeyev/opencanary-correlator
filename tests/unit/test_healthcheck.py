"""Container health probe: follows OCC_HEALTH_PORT and OCC_HEALTH_HOST."""

from __future__ import annotations

import threading
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from typing import Any

import pytest

from opencanary_correlator.healthcheck import (
    DEFAULT_HEALTH_PORT,
    LOOPBACK_HOST,
    main,
    parse_health_host,
    parse_health_port,
    probe,
)


def recording_probe(calls: list[tuple[str, int]]) -> Callable[[str, int], bool]:
    """Probe stand-in that records each (host, port) and reports success."""

    def probe(host: str, port: int) -> bool:
        calls.append((host, port))
        return True

    return probe


class FakeConnection:
    """Minimal HTTPConnection stand-in returning a fixed status."""

    def __init__(self, status: int) -> None:
        self.status = status

    def request(self, method: str, path: str) -> None:
        return None

    def getresponse(self) -> SimpleNamespace:
        return SimpleNamespace(status=self.status)

    def close(self) -> None:
        return None


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("8080", 8080),
        (" 9090 ", 9090),
        ("0", None),
        ("", None),
        ("   ", None),
    ],
)
def test_parse_health_port(raw: str, expected: int | None) -> None:
    assert parse_health_port(raw) == expected


@pytest.mark.parametrize("raw", ["-1", "65536", "abc"])
def test_parse_health_port_rejects_invalid_values(raw: str) -> None:
    with pytest.raises(ValueError):
        parse_health_port(raw)


def test_probe_accepts_only_200(monkeypatch: Any) -> None:
    statuses = iter([200, 503])
    monkeypatch.setattr(
        "opencanary_correlator.healthcheck.HTTPConnection",
        lambda *args, **kwargs: FakeConnection(next(statuses)),
    )

    assert probe("127.0.0.1", 8080) is True
    assert probe("127.0.0.1", 8080) is False


def test_probe_returns_false_when_nothing_listens(monkeypatch: Any) -> None:
    class BrokenConnection(FakeConnection):
        def request(self, method: str, path: str) -> None:
            raise OSError("connection refused")

    monkeypatch.setattr(
        "opencanary_correlator.healthcheck.HTTPConnection",
        lambda *args, **kwargs: BrokenConnection(0),
    )

    assert probe("127.0.0.1", 8080) is False


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (None, LOOPBACK_HOST),
        ("", LOOPBACK_HOST),
        ("   ", LOOPBACK_HOST),
        ("0.0.0.0", LOOPBACK_HOST),  # noqa: S104 - a value to parse, not a bind address
        ("::", LOOPBACK_HOST),
        ("[::]", LOOPBACK_HOST),
        ("127.0.0.1", "127.0.0.1"),
        (" 127.0.0.1 ", "127.0.0.1"),
        ("::1", "::1"),
        ("172.17.0.2", "172.17.0.2"),
    ],
)
def test_parse_health_host(raw: str | None, expected: str) -> None:
    assert parse_health_host(raw) == expected


def test_main_uses_the_default_port_and_loopback_when_unset() -> None:
    probed: list[tuple[str, int]] = []

    assert main(environ={}, probe_fn=recording_probe(probed)) == 0

    assert probed == [(LOOPBACK_HOST, DEFAULT_HEALTH_PORT)]


def test_main_probes_the_configured_port() -> None:
    probed: list[tuple[str, int]] = []

    assert (
        main(
            environ={"OCC_HEALTH_PORT": "9090"},
            probe_fn=recording_probe(probed),
        )
        == 0
    )

    assert probed == [(LOOPBACK_HOST, 9090)]


def test_main_dials_the_configured_host() -> None:
    """A loopback-only listener would otherwise be probed on the wrong address."""
    probed: list[tuple[str, int]] = []

    assert (
        main(
            environ={"OCC_HEALTH_PORT": "9090", "OCC_HEALTH_HOST": "::1"},
            probe_fn=recording_probe(probed),
        )
        == 0
    )

    assert probed == [("::1", 9090)]


def test_main_maps_a_wildcard_binding_to_loopback() -> None:
    probed: list[tuple[str, int]] = []

    assert (
        main(
            environ={"OCC_HEALTH_PORT": "8080", "OCC_HEALTH_HOST": "0.0.0.0"},  # noqa: S104 - input
            probe_fn=recording_probe(probed),
        )
        == 0
    )

    assert probed == [(LOOPBACK_HOST, 8080)]


@pytest.mark.parametrize("value", ["0", ""])
def test_main_succeeds_without_a_probe_when_disabled(value: str) -> None:
    probed: list[tuple[str, int]] = []

    assert main(environ={"OCC_HEALTH_PORT": value}, probe_fn=recording_probe(probed)) == 0

    assert probed == []


def test_main_reports_a_failed_probe(capsys: Any) -> None:
    assert main(environ={"OCC_HEALTH_PORT": "8080"}, probe_fn=lambda _host, _port: False) == 1

    assert "health probe failed on 127.0.0.1:8080" in capsys.readouterr().err


def test_main_probes_a_real_listener() -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path == "/healthz":
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"status":"ok"}')
            else:
                self.send_error(404)

        def log_message(self, fmt: str, *args: Any) -> None:
            return None

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = int(server.server_address[1])
        assert main(environ={"OCC_HEALTH_PORT": str(port)}) == 0
        # The listener is loopback-only, so a probe against 0.0.0.0 would fail.
        assert main(environ={"OCC_HEALTH_PORT": str(port), "OCC_HEALTH_HOST": "127.0.0.1"}) == 0
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_main_reports_an_invalid_port(capsys: Any) -> None:
    assert main(environ={"OCC_HEALTH_PORT": "not-a-port"}, probe_fn=lambda _host, _port: True) == 1

    assert "invalid OCC_HEALTH_PORT" in capsys.readouterr().err
