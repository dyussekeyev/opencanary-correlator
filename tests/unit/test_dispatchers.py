"""Dispatcher behaviour: payloads, retries, breaker and channel limits."""

from __future__ import annotations

import json
from typing import Any

import aiosmtplib
import httpx
import pytest

from opencanary_correlator.connectors.dispatchers import (
    CircuitBreaker,
    DiscordDispatcher,
    RetryPolicy,
    SlackDispatcher,
    SmtpDispatcher,
    TelegramDispatcher,
    WebhookDispatcher,
)
from opencanary_correlator.connectors.dispatchers.discord import (
    DISCORD_MAX_CONTENT,
    DISCORD_MAX_EMBED_DESCRIPTION,
)


async def no_sleep(_seconds: float) -> None:
    return None


def make_client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def scripted_handler(responses, calls):
    """Return responses in order (repeating the last), recording each request."""

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        item = responses[min(len(calls) - 1, len(responses) - 1)]
        if isinstance(item, Exception):
            raise item
        return item

    return handler


def fast_retry(**overrides) -> RetryPolicy:
    params = {"attempts": 3, "base_delay": 0.0, "max_delay": 0.0, "jitter": 0.0}
    params.update(overrides)
    return RetryPolicy(**params)


async def test_webhook_posts_incident_and_reports_success(incident_factory) -> None:
    calls: list[httpx.Request] = []
    client = make_client(scripted_handler([httpx.Response(200)], calls))
    dispatcher = WebhookDispatcher(url="https://siem.test/hook", client=client)
    try:
        result = await dispatcher.dispatch(incident_factory())
    finally:
        await dispatcher.aclose()

    assert result.status == "success"
    payload = json.loads(calls[0].content)
    assert payload["title"] == "FTP Login Attempt by 10.0.0.5 on canary-1 (10.0.0.2)"
    assert "FTP Login Attempt" in payload["text"]
    assert payload["key"] == "incident:ftplogin:10.0.0.5:1418997029"
    assert "PASSWORD" not in json.dumps(payload)


async def test_webhook_retries_server_errors(incident_factory) -> None:
    calls: list[httpx.Request] = []
    client = make_client(
        scripted_handler([httpx.Response(500), httpx.Response(503), httpx.Response(200)], calls)
    )
    dispatcher = WebhookDispatcher(
        url="https://siem.test/hook", client=client, retry=fast_retry(), sleep=no_sleep
    )

    result = await dispatcher.dispatch(incident_factory())

    assert result.status == "success"
    assert len(calls) == 3


async def test_webhook_exhausts_retries(incident_factory) -> None:
    calls: list[httpx.Request] = []
    client = make_client(scripted_handler([httpx.Response(500)], calls))
    dispatcher = WebhookDispatcher(
        url="https://siem.test/hook", client=client, retry=fast_retry(), sleep=no_sleep
    )

    result = await dispatcher.dispatch(incident_factory())

    assert result.status == "error"
    assert result.detail == "http_500"
    assert len(calls) == 3


async def test_webhook_honours_retry_after(incident_factory) -> None:
    calls: list[httpx.Request] = []
    client = make_client(
        scripted_handler(
            [httpx.Response(429, headers={"Retry-After": "0"}), httpx.Response(200)],
            calls,
        )
    )
    dispatcher = WebhookDispatcher(
        url="https://siem.test/hook", client=client, retry=fast_retry(), sleep=no_sleep
    )

    result = await dispatcher.dispatch(incident_factory())

    assert result.status == "success"
    assert len(calls) == 2


async def test_webhook_does_not_retry_client_errors(incident_factory) -> None:
    calls: list[httpx.Request] = []
    client = make_client(scripted_handler([httpx.Response(400)], calls))
    dispatcher = WebhookDispatcher(
        url="https://siem.test/hook", client=client, retry=fast_retry(), sleep=no_sleep
    )

    result = await dispatcher.dispatch(incident_factory())

    assert result.status == "error"
    assert len(calls) == 1


async def test_webhook_retries_transport_errors(incident_factory) -> None:
    calls: list[httpx.Request] = []
    client = make_client(scripted_handler([httpx.ConnectError("no route")], calls))
    dispatcher = WebhookDispatcher(
        url="https://siem.test/hook", client=client, retry=fast_retry(), sleep=no_sleep
    )

    result = await dispatcher.dispatch(incident_factory())

    assert result.status == "error"
    assert result.detail == "ConnectError"
    assert len(calls) == 3


async def test_circuit_breaker_skips_after_repeated_failures(store, incident_factory) -> None:
    calls: list[httpx.Request] = []
    client = make_client(scripted_handler([httpx.Response(500)], calls))
    breaker = CircuitBreaker(store, "webhook", failure_threshold=2, cooldown=60)
    dispatcher = WebhookDispatcher(
        url="https://siem.test/hook",
        client=client,
        retry=fast_retry(),
        sleep=no_sleep,
        breaker=breaker,
    )

    assert (await dispatcher.dispatch(incident_factory())).status == "error"
    assert (await dispatcher.dispatch(incident_factory())).status == "error"
    skipped = await dispatcher.dispatch(incident_factory())

    assert skipped.status == "skipped"
    assert skipped.detail == "circuit_open"
    assert len(calls) == 6


async def test_slack_uses_the_compact_report(incident_factory) -> None:
    calls: list[httpx.Request] = []
    client = make_client(scripted_handler([httpx.Response(200)], calls))
    dispatcher = SlackDispatcher(url="https://hooks.slack.test/x", client=client)

    result = await dispatcher.dispatch(incident_factory())

    assert result.status == "success"
    assert json.loads(calls[0].content)["text"].startswith("Canary Incident: FTP Login Attempt.")


async def test_telegram_posts_chat_and_truncated_text(incident_factory) -> None:
    class LongIncident:
        key = "k"

        def format_title(self) -> str:
            return "title"

        def format_report(self) -> str:
            return "report"

        def format_report_short(self) -> str:
            return "x" * 5000

    calls: list[httpx.Request] = []
    client = make_client(scripted_handler([httpx.Response(200)], calls))
    dispatcher = TelegramDispatcher(token="123:secret-token", chat_id="-100500", client=client)

    result = await dispatcher.dispatch(LongIncident())

    assert result.status == "success"
    assert str(calls[0].url) == "https://api.telegram.org/bot123:secret-token/sendMessage"
    payload = json.loads(calls[0].content)
    assert payload["chat_id"] == "-100500"
    assert len(payload["text"]) == 4096


@pytest.mark.parametrize("status", [200, 204])
async def test_discord_accepts_both_success_statuses(incident_factory, status: int) -> None:
    calls: list[httpx.Request] = []
    client = make_client(scripted_handler([httpx.Response(status)], calls))
    dispatcher = DiscordDispatcher(url="https://discord.test/webhook", client=client)

    result = await dispatcher.dispatch(incident_factory())

    assert result.status == "success"
    assert "content" in json.loads(calls[0].content)


async def test_discord_uses_embed_for_long_reports() -> None:
    class LongIncident:
        key = "k"

        def format_title(self) -> str:
            return "A very long incident"

        def format_report(self) -> str:
            return "r" * 6000

        def format_report_short(self) -> str:
            return "s" * (DISCORD_MAX_CONTENT + 1)

    calls: list[httpx.Request] = []
    client = make_client(scripted_handler([httpx.Response(204)], calls))
    dispatcher = DiscordDispatcher(url="https://discord.test/webhook", client=client)

    result = await dispatcher.dispatch(LongIncident())

    assert result.status == "success"
    payload = json.loads(calls[0].content)
    assert "content" not in payload
    assert len(payload["embeds"][0]["description"]) == DISCORD_MAX_EMBED_DESCRIPTION


async def test_smtp_sends_email(incident_factory) -> None:
    sent: list[tuple[object, dict]] = []

    async def fake_send(message, **kwargs) -> Any:
        sent.append((message, kwargs))
        return ({}, "ok")

    dispatcher = SmtpDispatcher(
        host="smtp.test",
        port=587,
        sender="alerts@example.test",
        recipients=["soc@example.test"],
        send=fake_send,
    )

    result = await dispatcher.dispatch(incident_factory())

    assert result.status == "success"
    message, kwargs = sent[0]
    assert message["Subject"] == "FTP Login Attempt by 10.0.0.5 on canary-1 (10.0.0.2)"
    assert message["To"] == "soc@example.test"
    assert kwargs["hostname"] == "smtp.test"
    assert kwargs["start_tls"] is True


async def test_smtp_retries_and_reports_failure(incident_factory) -> None:
    attempts = 0

    async def failing_send(message, **kwargs) -> Any:
        nonlocal attempts
        attempts += 1
        raise aiosmtplib.SMTPException("relay down")

    dispatcher = SmtpDispatcher(
        host="smtp.test",
        port=25,
        sender="alerts@example.test",
        recipients=["soc@example.test"],
        retry=fast_retry(),
        send=failing_send,
        sleep=no_sleep,
    )

    result = await dispatcher.dispatch(incident_factory())

    assert result.status == "error"
    assert attempts == 3


async def test_smtp_without_recipients_is_skipped(incident_factory) -> None:
    dispatcher = SmtpDispatcher(
        host="smtp.test",
        port=25,
        sender="alerts@example.test",
        recipients=[],
    )

    result = await dispatcher.dispatch(incident_factory())

    assert result.status == "skipped"


@pytest.mark.parametrize("status", [200, 201, 202, 204])
async def test_expected_statuses_are_configurable(incident_factory, status: int) -> None:
    calls: list[httpx.Request] = []
    client = make_client(scripted_handler([httpx.Response(status)], calls))
    dispatcher = WebhookDispatcher(
        url="https://siem.test/hook", client=client, expected_status=(status,)
    )

    result = await dispatcher.dispatch(incident_factory())

    assert result.status == "success"
