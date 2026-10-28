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
    breaker_name,
)
from opencanary_correlator.connectors.dispatchers.discord import (
    DISCORD_MAX_CONTENT,
    DISCORD_MAX_EMBED_DESCRIPTION,
)
from opencanary_correlator.enrichment.models import (
    Enrichment,
    GeoInfo,
    VirusTotalReport,
)

ATTACKER_CONTEXT = Enrichment(
    geo=GeoInfo(
        country_code="KZ",
        country="Kazakhstan",
        city="Almaty",
        asn=202958,
        as_org='LLP "Kompaniya Hoster.KZ"',
    ),
    virus_total=VirusTotalReport(
        malicious=0,
        suspicious=1,
        harmless=70,
        undetected=23,
        reputation=0,
        checked="2026-10-26",
    ),
    virus_total_status="ok",
)


async def no_sleep(_seconds: float) -> None:
    return None


def make_client(handler: Any) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def test_breaker_name_is_per_endpoint_and_hides_the_secret() -> None:
    endpoint = "https://hooks.test/services/secret-token"

    name = breaker_name("webhook", endpoint)

    assert name == breaker_name("webhook", endpoint)
    assert name.startswith("webhook:")
    assert "secret-token" not in name
    assert name != breaker_name("webhook", "https://hooks.test/services/other")
    assert name != breaker_name("slack", endpoint)


def scripted_handler(responses: Any, calls: Any) -> Any:
    """Return responses in order (repeating the last), recording each request."""

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        item = responses[min(len(calls) - 1, len(responses) - 1)]
        if isinstance(item, Exception):
            raise item
        assert isinstance(item, httpx.Response)
        return item

    return handler


def fast_retry(**overrides: Any) -> RetryPolicy:
    params: dict[str, Any] = {"attempts": 3, "base_delay": 0.0, "max_delay": 0.0, "jitter": 0.0}
    params.update(overrides)
    return RetryPolicy(**params)


async def test_webhook_posts_incident_and_reports_success(incident_factory: Any) -> None:
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
    # Without enrichment the document stays exactly the legacy three keys.
    assert set(payload) == {"title", "text", "key"}


async def test_webhook_carries_the_attacker_context_as_structured_json(
    incident_factory: Any,
) -> None:
    """A SIEM consumer gets the geo/VT values without parsing the message."""
    calls: list[httpx.Request] = []
    client = make_client(scripted_handler([httpx.Response(200)], calls))
    dispatcher = WebhookDispatcher(url="https://siem.test/hook", client=client)
    try:
        await dispatcher.dispatch(incident_factory(enrichment=ATTACKER_CONTEXT))
    finally:
        await dispatcher.aclose()

    payload = json.loads(calls[0].content)
    assert payload["enrichment"] == {
        "geo": {
            "country_code": "KZ",
            "country": "Kazakhstan",
            "city": "Almaty",
            "asn": 202958,
            "as_org": 'LLP "Kompaniya Hoster.KZ"',
        },
        "virustotal": {
            "malicious": 0,
            "suspicious": 1,
            "detections": 1,
            "total": 94,
            "reputation": 0,
            "checked": "2026-10-26",
        },
    }
    # The legacy `text` field is untouched at the minimal level, so parsers
    # keyed on it keep working while they migrate to the structured object.
    assert "Location" not in payload["text"]


async def test_webhook_reports_a_spent_quota_without_a_verdict(incident_factory: Any) -> None:
    calls: list[httpx.Request] = []
    client = make_client(scripted_handler([httpx.Response(200)], calls))
    dispatcher = WebhookDispatcher(url="https://siem.test/hook", client=client)
    enrichment = Enrichment(geo=GeoInfo(country="Kazakhstan"), virus_total_status="quota")
    try:
        await dispatcher.dispatch(incident_factory(enrichment=enrichment))
    finally:
        await dispatcher.aclose()

    payload = json.loads(calls[0].content)
    assert payload["enrichment"]["geo"]["country"] == "Kazakhstan"
    assert payload["enrichment"]["virustotal_status"] == "quota"


async def test_webhook_retries_server_errors(incident_factory: Any) -> None:
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


async def test_webhook_exhausts_retries(incident_factory: Any) -> None:
    calls: list[httpx.Request] = []
    client = make_client(scripted_handler([httpx.Response(500)], calls))
    dispatcher = WebhookDispatcher(
        url="https://siem.test/hook", client=client, retry=fast_retry(), sleep=no_sleep
    )

    result = await dispatcher.dispatch(incident_factory())

    assert result.status == "error"
    assert result.detail == "http_500"
    assert len(calls) == 3


async def test_webhook_honours_retry_after(incident_factory: Any) -> None:
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


async def test_webhook_does_not_retry_client_errors(incident_factory: Any) -> None:
    calls: list[httpx.Request] = []
    client = make_client(scripted_handler([httpx.Response(400)], calls))
    dispatcher = WebhookDispatcher(
        url="https://siem.test/hook", client=client, retry=fast_retry(), sleep=no_sleep
    )

    result = await dispatcher.dispatch(incident_factory())

    assert result.status == "error"
    assert len(calls) == 1


async def test_webhook_retries_transport_errors(incident_factory: Any) -> None:
    calls: list[httpx.Request] = []
    client = make_client(scripted_handler([httpx.ConnectError("no route")], calls))
    dispatcher = WebhookDispatcher(
        url="https://siem.test/hook", client=client, retry=fast_retry(), sleep=no_sleep
    )

    result = await dispatcher.dispatch(incident_factory())

    assert result.status == "error"
    assert result.detail == "ConnectError"
    assert len(calls) == 3


async def test_circuit_breaker_skips_after_repeated_failures(
    store: Any, incident_factory: Any
) -> None:
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


async def test_slack_minimal_detail_uses_the_compact_report(incident_factory: Any) -> None:
    calls: list[httpx.Request] = []
    client = make_client(scripted_handler([httpx.Response(200)], calls))
    dispatcher = SlackDispatcher(url="https://hooks.slack.test/x", client=client, detail="minimal")

    result = await dispatcher.dispatch(incident_factory())

    assert result.status == "success"
    assert json.loads(calls[0].content)["text"].startswith("Canary Incident: FTP Login Attempt.")


async def test_slack_sends_the_multiline_layout_by_default(incident_factory: Any) -> None:
    calls: list[httpx.Request] = []
    client = make_client(scripted_handler([httpx.Response(200)], calls))
    dispatcher = SlackDispatcher(url="https://hooks.slack.test/x", client=client)

    await dispatcher.dispatch(incident_factory())

    text = json.loads(calls[0].content)["text"]
    assert "\r\n" in text
    assert "*Instance:* canary-1" in text
    assert "*Attacker:* 10.0.0.5:40000" in text
    assert "*Log:* USERNAME=admin" in text


async def test_telegram_posts_chat_and_truncated_text(incident_factory: Any) -> None:
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
    dispatcher = TelegramDispatcher(
        token="123:secret-token", chat_id="-100500", client=client, detail="minimal"
    )

    result = await dispatcher.dispatch(LongIncident())

    assert result.status == "success"
    assert str(calls[0].url) == "https://api.telegram.org/bot123:secret-token/sendMessage"
    payload = json.loads(calls[0].content)
    assert payload["chat_id"] == "-100500"
    assert len(payload["text"]) == 4096
    assert "parse_mode" not in payload


async def test_telegram_sends_escaped_markdownv2_by_default(incident_factory: Any) -> None:
    calls: list[httpx.Request] = []
    client = make_client(scripted_handler([httpx.Response(200)], calls))
    dispatcher = TelegramDispatcher(token="123:secret-token", chat_id="-100500", client=client)

    await dispatcher.dispatch(incident_factory(node_id="canary (lab)"))

    payload = json.loads(calls[0].content)
    assert payload["parse_mode"] == "MarkdownV2"
    assert "\r\n" in payload["text"]
    # Reserved MarkdownV2 characters must be escaped or Telegram rejects the message.
    assert "canary \\(lab\\)" in payload["text"]
    assert "10\\.0\\.0\\.5" in payload["text"]


async def test_telegram_token_never_appears_in_the_dispatch_result(incident_factory: Any) -> None:
    token = "123456:very-secret-token"

    def failing_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"cannot reach {request.url}")

    client = make_client(failing_handler)
    dispatcher = TelegramDispatcher(token=token, chat_id="-100500", client=client)

    result = await dispatcher.dispatch(incident_factory())

    assert result.status == "error"
    assert token not in repr(result)
    assert "very-secret-token" not in repr(result)


@pytest.mark.parametrize("status", [200, 204])
async def test_discord_accepts_both_success_statuses(incident_factory: Any, status: int) -> None:
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
    dispatcher = DiscordDispatcher(
        url="https://discord.test/webhook", client=client, detail="minimal"
    )

    result = await dispatcher.dispatch(LongIncident())

    assert result.status == "success"
    payload = json.loads(calls[0].content)
    assert "content" not in payload
    assert len(payload["embeds"][0]["description"]) == DISCORD_MAX_EMBED_DESCRIPTION


async def test_smtp_sends_email(incident_factory: Any) -> None:
    sent: list[tuple[Any, dict[str, Any]]] = []

    async def fake_send(message: Any, **kwargs: Any) -> Any:
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
    assert kwargs["use_tls"] is False


async def test_smtp_default_layout_shows_the_attacker_context(incident_factory: Any) -> None:
    """Email is read by a human, so the readable layout is the default."""
    sent: list[Any] = []

    async def fake_send(message: Any, **kwargs: Any) -> Any:
        sent.append(message)
        return ({}, "ok")

    dispatcher = SmtpDispatcher(
        host="smtp.test",
        port=587,
        sender="alerts@example.test",
        recipients=["soc@example.test"],
        send=fake_send,
    )

    result = await dispatcher.dispatch(incident_factory(enrichment=ATTACKER_CONTEXT))

    assert result.status == "success"
    body = sent[0].get_content()
    assert "Instance: canary-1" in body
    assert "Location: Kazakhstan" in body
    assert "VT: 0/94 malicious (+1 suspicious)" in body


async def test_smtp_subject_cannot_be_split_by_a_payload(incident_factory: Any) -> None:
    sent: list[Any] = []

    async def fake_send(message: Any, **kwargs: Any) -> Any:
        sent.append(message)
        return ({}, "ok")

    dispatcher = SmtpDispatcher(
        host="smtp.test",
        port=25,
        sender="alerts@example.test",
        recipients=["soc@example.test"],
        send=fake_send,
    )

    result = await dispatcher.dispatch(incident_factory(node_id="canary\r\nBcc: evil@example.test"))

    assert result.status == "success"
    subject = sent[0]["Subject"]
    assert "\r" not in subject
    assert "\n" not in subject
    # Flattened, not dropped: the forged header stays inside the subject line.
    assert "Bcc: evil@example.test" in subject
    assert "Bcc" not in sent[0]


async def test_a_message_rendering_error_is_reported_not_raised(
    monkeypatch: Any, incident_factory: Any
) -> None:
    async def fake_send(message: Any, **kwargs: Any) -> Any:  # pragma: no cover - must not run
        raise AssertionError("send must not be called when rendering fails")

    def boom(self: Any, incident: Any) -> Any:
        raise ValueError("bad header")

    monkeypatch.setattr(SmtpDispatcher, "build_message", boom)
    dispatcher = SmtpDispatcher(
        host="smtp.test",
        port=25,
        sender="alerts@example.test",
        recipients=["soc@example.test"],
        send=fake_send,
    )

    result = await dispatcher.dispatch(incident_factory())

    assert result.status == "error"
    assert result.detail == "ValueError"
    assert "bad header" not in repr(result)


async def test_smtp_uses_implicit_tls(incident_factory: Any) -> None:
    sent: list[dict[str, Any]] = []

    async def fake_send(message: Any, **kwargs: Any) -> Any:
        sent.append(kwargs)
        return ({}, "ok")

    dispatcher = SmtpDispatcher(
        host="smtp.test",
        port=465,
        sender="alerts@example.test",
        recipients=["soc@example.test"],
        start_tls=False,
        use_tls=True,
        send=fake_send,
    )

    result = await dispatcher.dispatch(incident_factory())

    assert result.status == "success"
    assert sent[0]["start_tls"] is False
    assert sent[0]["use_tls"] is True


async def test_smtp_retries_and_reports_failure(incident_factory: Any) -> None:
    attempts = 0

    async def failing_send(message: Any, **kwargs: Any) -> Any:
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


async def test_smtp_without_recipients_is_skipped(incident_factory: Any) -> None:
    dispatcher = SmtpDispatcher(
        host="smtp.test",
        port=25,
        sender="alerts@example.test",
        recipients=[],
    )

    result = await dispatcher.dispatch(incident_factory())

    assert result.status == "skipped"


@pytest.mark.parametrize("status", [200, 201, 202, 204])
async def test_expected_statuses_are_configurable(incident_factory: Any, status: int) -> None:
    calls: list[httpx.Request] = []
    client = make_client(scripted_handler([httpx.Response(status)], calls))
    dispatcher = WebhookDispatcher(
        url="https://siem.test/hook", client=client, expected_status=(status,)
    )

    result = await dispatcher.dispatch(incident_factory())

    assert result.status == "success"
