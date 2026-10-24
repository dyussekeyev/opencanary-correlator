"""Dispatcher tests against real loopback HTTP and SMTP servers."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import Any

import pytest

from opencanary_correlator.connectors.dispatchers import (
    CircuitBreaker,
    DiscordDispatcher,
    RetryPolicy,
    SlackDispatcher,
    SmtpDispatcher,
    WebhookDispatcher,
    breaker_name,
)

pytestmark = pytest.mark.integration

_REASONS = {
    200: "OK",
    204: "No Content",
    400: "Bad Request",
    429: "Too Many Requests",
    500: "Internal Server Error",
    503: "Service Unavailable",
}


class MockHTTPServer:
    """One-request-per-connection HTTP server returning scripted responses."""

    def __init__(self, responses: list[tuple[int, dict[str, str]]]) -> None:
        self._responses = responses
        self.requests: list[SimpleNamespace] = []
        self._server: asyncio.AbstractServer | None = None
        self.port = 0

    async def __aenter__(self) -> MockHTTPServer:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        sockets = self._server.sockets or ()
        self.port = int(sockets[0].getsockname()[1])
        return self

    async def __aexit__(self, *_exc: object) -> None:
        assert self._server is not None
        self._server.close()
        await self._server.wait_closed()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            request_line = (await reader.readline()).decode("latin-1").strip()
            headers: dict[str, str] = {}
            while True:
                line = await reader.readline()
                if line in (b"\r\n", b"\n", b""):
                    break
                name, _, value = line.decode("latin-1").partition(":")
                headers[name.strip().lower()] = value.strip()
            body = await reader.readexactly(int(headers.get("content-length", "0")))
            self.requests.append(SimpleNamespace(line=request_line, headers=headers, body=body))
            status, extra = self._responses[min(len(self.requests) - 1, len(self._responses) - 1)]
            headers = "".join(f"{name}: {value}\r\n" for name, value in extra.items())
            if status == 204:
                # A 204 response must not carry a body.
                writer.write(
                    f"HTTP/1.1 204 {_REASONS[204]}\r\n{headers}Connection: close\r\n\r\n".encode(
                        "latin-1"
                    )
                )
            else:
                payload = b'{"ok": true}'
                raw = (
                    f"HTTP/1.1 {status} {_REASONS[status]}\r\n"
                    "Content-Type: application/json\r\n"
                    f"Content-Length: {len(payload)}\r\n"
                    f"{headers}Connection: close\r\n\r\n"
                )
                writer.write(raw.encode("latin-1") + payload)
            await writer.drain()
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:  # pragma: no cover - peer already gone
                pass

    def url(self, path: str = "/hook") -> str:
        return f"http://127.0.0.1:{self.port}{path}"


class MockSMTPServer:
    """Minimal ESMTP server that records DATA payloads."""

    def __init__(self) -> None:
        self.messages: list[tuple[dict[str, Any], bytes]] = []
        self._server: asyncio.AbstractServer | None = None
        self.port = 0

    async def __aenter__(self) -> MockSMTPServer:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        sockets = self._server.sockets or ()
        self.port = int(sockets[0].getsockname()[1])
        return self

    async def __aexit__(self, *_exc: object) -> None:
        assert self._server is not None
        self._server.close()
        await self._server.wait_closed()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        envelope: dict[str, Any] = {"mail_from": None, "rcpt": []}

        def reply(line: str) -> None:
            writer.write((line + "\r\n").encode("latin-1"))

        reply("220 mock ESMTP")
        await writer.drain()
        try:
            while True:
                raw = await reader.readline()
                if not raw:
                    return
                command = raw.decode("utf-8", "replace").strip()
                upper = command.upper()
                if upper.startswith(("EHLO", "HELO")):
                    reply("250-mock")
                    reply("250 HELP")
                elif upper.startswith("MAIL FROM"):
                    envelope["mail_from"] = command
                    reply("250 OK")
                elif upper.startswith("RCPT TO"):
                    envelope["rcpt"].append(command)
                    reply("250 OK")
                elif upper.startswith("DATA"):
                    reply("354 End data with <CR><LF>.<CR><LF>")
                    await writer.drain()
                    data = await reader.readuntil(b"\r\n.\r\n")
                    self.messages.append(
                        (
                            {
                                "mail_from": envelope["mail_from"],
                                "rcpt": list(envelope["rcpt"]),
                            },
                            data,
                        )
                    )
                    reply("250 queued")
                elif upper.startswith("QUIT"):
                    reply("221 Bye")
                    await writer.drain()
                    return
                else:
                    reply("250 OK")
                await writer.drain()
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:  # pragma: no cover - peer already gone
                pass


def no_jitter_policy(**overrides: Any) -> RetryPolicy:
    params: dict[str, Any] = {
        "attempts": 3,
        "base_delay": 0.1,
        "max_delay": 1.0,
        "jitter": 0.0,
    }
    params.update(overrides)
    return RetryPolicy(**params)


class Delays:
    """Records the sleeps requested by a retry policy without waiting."""

    def __init__(self) -> None:
        self.values: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.values.append(seconds)
        await asyncio.sleep(0)


async def test_webhook_delivers_over_a_real_socket(incident_factory) -> None:
    async with MockHTTPServer([(200, {})]) as server:
        dispatcher = WebhookDispatcher(url=server.url("/siem"))
        try:
            result = await dispatcher.dispatch(incident_factory())
        finally:
            await dispatcher.aclose()

    assert result.status == "success"
    request = server.requests[0]
    assert request.line == "POST /siem HTTP/1.1"
    assert request.headers["content-type"] == "application/json"
    payload = json.loads(request.body)
    assert payload["key"] == "incident:ftplogin:10.0.0.5:1418997029"
    assert "FTP Login Attempt" in payload["title"]


async def test_webhook_retries_server_errors_with_backoff(incident_factory) -> None:
    delays = Delays()
    async with MockHTTPServer([(503, {}), (500, {}), (200, {})]) as server:
        dispatcher = WebhookDispatcher(
            url=server.url(),
            retry=no_jitter_policy(),
            sleep=delays,
        )
        try:
            result = await dispatcher.dispatch(incident_factory())
        finally:
            await dispatcher.aclose()

    assert result.status == "success"
    assert len(server.requests) == 3
    assert delays.values == [0.1, 0.2]


async def test_webhook_honours_retry_after(incident_factory) -> None:
    delays = Delays()
    async with MockHTTPServer([(429, {"Retry-After": "2"}), (200, {})]) as server:
        dispatcher = WebhookDispatcher(url=server.url(), retry=no_jitter_policy(), sleep=delays)
        try:
            result = await dispatcher.dispatch(incident_factory())
        finally:
            await dispatcher.aclose()

    assert result.status == "success"
    assert delays.values == [2.0]


async def test_webhook_does_not_retry_client_errors(incident_factory) -> None:
    delays = Delays()
    async with MockHTTPServer([(400, {})]) as server:
        dispatcher = WebhookDispatcher(url=server.url(), retry=no_jitter_policy(), sleep=delays)
        try:
            result = await dispatcher.dispatch(incident_factory())
        finally:
            await dispatcher.aclose()

    assert result.status == "error"
    assert result.detail == "http_400"
    assert len(server.requests) == 1
    assert delays.values == []


async def test_circuit_breaker_stops_calls_after_repeated_failures(incident_factory, store) -> None:
    async with MockHTTPServer([(503, {})]) as server:
        breaker = CircuitBreaker(store, "webhook", failure_threshold=1, cooldown=60)
        dispatcher = WebhookDispatcher(
            url=server.url(),
            retry=no_jitter_policy(attempts=1, base_delay=0.0),
            breaker=breaker,
        )
        try:
            first = await dispatcher.dispatch(incident_factory())
            second = await dispatcher.dispatch(incident_factory())
        finally:
            await dispatcher.aclose()

    assert first.status == "error"
    assert second.status == "skipped"
    assert second.detail == "circuit_open"
    assert len(server.requests) == 1


async def test_circuit_breaker_is_scoped_to_one_endpoint(incident_factory, store) -> None:
    async with (
        MockHTTPServer([(503, {})]) as dead,
        MockHTTPServer([(200, {})]) as alive,
    ):
        dead_dispatcher = WebhookDispatcher(
            url=dead.url("/dead"),
            retry=no_jitter_policy(attempts=1, base_delay=0.0),
            breaker=CircuitBreaker(
                store,
                breaker_name("webhook", dead.url("/dead")),
                failure_threshold=1,
            ),
        )
        alive_dispatcher = WebhookDispatcher(
            url=alive.url("/alive"),
            retry=no_jitter_policy(attempts=1, base_delay=0.0),
            breaker=CircuitBreaker(
                store,
                breaker_name("webhook", alive.url("/alive")),
                failure_threshold=1,
            ),
        )
        try:
            assert (await dead_dispatcher.dispatch(incident_factory())).status == "error"
            assert (await dead_dispatcher.dispatch(incident_factory())).detail == "circuit_open"
            assert (await alive_dispatcher.dispatch(incident_factory())).status == "success"
        finally:
            await dead_dispatcher.aclose()
            await alive_dispatcher.aclose()

    assert len(dead.requests) == 1
    assert len(alive.requests) == 1


async def test_slack_and_discord_use_short_reports_over_http(incident_factory) -> None:
    incident = incident_factory()
    async with MockHTTPServer([(200, {}), (200, {})]) as server:
        slack = SlackDispatcher(url=server.url("/slack"))
        discord = DiscordDispatcher(url=server.url("/discord"))
        try:
            slack_result = await slack.dispatch(incident)
            discord_result = await discord.dispatch(incident)
        finally:
            await slack.aclose()
            await discord.aclose()

    assert slack_result.status == "success"
    assert discord_result.status == "success"
    slack_payload = json.loads(server.requests[0].body)
    discord_payload = json.loads(server.requests[1].body)
    assert "FTP Login Attempt" in slack_payload["text"]
    assert "FTP Login Attempt" in discord_payload["content"]


async def test_discord_accepts_204_from_a_real_server(incident_factory) -> None:
    async with MockHTTPServer([(204, {})]) as server:
        dispatcher = DiscordDispatcher(url=server.url("/discord"))
        try:
            result = await dispatcher.dispatch(incident_factory())
        finally:
            await dispatcher.aclose()

    assert result.status == "success"
    assert "content" in json.loads(server.requests[0].body)


class LongIncident:
    """Incident whose short report exceeds Discord's limit."""

    key = "incident:ftplogin:10.0.0.5:1418997029"

    def format_title(self) -> str:
        return "FTP Login Attempt"

    def format_report(self) -> str:
        return "x" * 5000

    def format_report_short(self) -> str:
        return "x" * 2500


async def test_discord_switches_to_embed_for_long_reports() -> None:
    async with MockHTTPServer([(200, {})]) as server:
        dispatcher = DiscordDispatcher(url=server.url("/discord"))
        try:
            result = await dispatcher.dispatch(LongIncident())
        finally:
            await dispatcher.aclose()

    assert result.status == "success"
    payload = json.loads(server.requests[0].body)
    assert "content" not in payload
    assert len(payload["embeds"][0]["description"]) == 4096


async def test_smtp_delivers_through_a_real_server(incident_factory) -> None:
    async with MockSMTPServer() as server:
        dispatcher = SmtpDispatcher(
            host="127.0.0.1",
            port=server.port,
            sender="canary@example.test",
            recipients=["soc@example.test"],
            start_tls=False,
            retry=no_jitter_policy(attempts=1),
        )
        try:
            result = await dispatcher.dispatch(incident_factory())
        finally:
            await dispatcher.aclose()

    assert result.status == "success"
    envelope, data = server.messages[0]
    assert "canary@example.test" in envelope["mail_from"]
    assert any("soc@example.test" in recipient for recipient in envelope["rcpt"])
    text = data.decode("utf-8", "replace")
    assert "Subject: FTP Login Attempt by 10.0.0.5 on canary-1 (10.0.0.2)" in text
    assert "FTP Login Attempt" in text
