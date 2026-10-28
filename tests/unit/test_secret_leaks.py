"""Cross-sink canary: configured and captured secrets never leave the process.

The Telegram token leak (``httpx`` logging the full request URL) was one instance
of a whole class: a secret reaching a sink nobody looked at. This test pushes a
real dispatch of every channel through the real log pipeline and asserts that no
secret appears in the log file, on stderr, or in an outbound message body.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from pydantic import SecretStr

from opencanary_correlator.cli import describe_settings, log_secrets
from opencanary_correlator.connectors.dispatchers import (
    DiscordDispatcher,
    SlackDispatcher,
    SmtpDispatcher,
    TelegramDispatcher,
    WebhookDispatcher,
)
from opencanary_correlator.log_setup import configure_logging

TELEGRAM_TOKEN = "123456:TELEGRAM-SECRET"
SLACK_URL = "https://hooks.slack.com/services/T1/B2/SLACK-SECRET"
DISCORD_URL = "https://discord.com/api/webhooks/1/DISCORD-SECRET"
#: The secret sits in a path segment of an arbitrary host, where no host-based
#: pattern applies: only the exact-match redaction of the configured URL covers it.
WEBHOOK_URL = "https://siem.example/hook/ARBITRARY-SECRET"
SMTP_PASSWORD = "SMTP-SECRET"
CAPTURED_PASSWORD = "CAPTURED-SECRET"

SECRETS = (
    TELEGRAM_TOKEN,
    "TELEGRAM-SECRET",
    "SLACK-SECRET",
    "DISCORD-SECRET",
    "ARBITRARY-SECRET",
    SMTP_PASSWORD,
    CAPTURED_PASSWORD,
)


@pytest.fixture
def captured_incident(incident_factory: Any) -> Any:
    """An incident whose stored `logdata` holds a password the canary captured."""
    return incident_factory(
        logdata=json.dumps([{"USERNAME": "admin", "PASSWORD": CAPTURED_PASSWORD}])
    )


async def test_no_secret_reaches_a_log_or_an_outbound_body(
    captured_incident: Any, settings_factory: Any, tmp_path: Any, capsys: Any
) -> None:
    requests: list[httpx.Request] = []
    sent: list[Any] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"ok": True})

    async def fake_send(message: Any, **kwargs: Any) -> Any:
        sent.append(message)
        return ({}, "ok")

    settings = settings_factory(
        telegram_token=TELEGRAM_TOKEN,
        slack_webhooks=[SLACK_URL],
        discord_webhooks=[DISCORD_URL],
        webhook_urls=[WEBHOOK_URL],
        smtp_password=SMTP_PASSWORD,
    )
    target = tmp_path / "correlator.log"
    # Same wiring as `main()`: the configured endpoints are passed to the log
    # pipeline as literal secrets, plus the pattern-based redaction.
    configure_logging(settings.log_level, target, secrets=log_secrets(settings))
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    dispatchers = [
        TelegramDispatcher(token=TELEGRAM_TOKEN, chat_id="-100", client=client, detail="detailed"),
        SlackDispatcher(url=SLACK_URL, client=client, detail="detailed"),
        DiscordDispatcher(url=DISCORD_URL, client=client, detail="detailed"),
        WebhookDispatcher(url=WEBHOOK_URL, client=client, detail="detailed"),
        SmtpDispatcher(
            host="smtp.test",
            port=25,
            sender="alerts@example.test",
            recipients=["soc@example.test"],
            detail="detailed",
            password=SecretStr(SMTP_PASSWORD),
            send=fake_send,
        ),
    ]
    try:
        for dispatcher in dispatchers:
            result = await dispatcher.dispatch(captured_incident)
            assert result.status == "success", (dispatcher.name, result)
    finally:
        await client.aclose()

    stderr = capsys.readouterr().err
    log_text = target.read_text(encoding="utf-8")
    outbound = "".join(request.content.decode("utf-8") for request in requests)
    outbound += "".join(str(message.get_content()) for message in sent)

    for secret in SECRETS:
        assert secret not in log_text, f"{secret} leaked into the log file"
        assert secret not in stderr, f"{secret} leaked into stderr"
        assert secret not in outbound, f"{secret} leaked into a delivered message"

    # The logs still have to be useful: the request lines are there, just masked.
    assert "api.telegram.org/bot***/sendMessage" in log_text
    assert "hooks.slack.com/services/***" in log_text
    assert "siem.example" in log_text
    # The alert shows the log entry with the credential masked, not dropped.
    assert "PASSWORD=***" in outbound


def test_no_secret_reaches_repr_or_check_config(settings_factory: Any) -> None:
    settings = settings_factory(
        telegram_token=TELEGRAM_TOKEN,
        slack_webhooks=[SLACK_URL],
        discord_webhooks=[DISCORD_URL],
        webhook_urls=[WEBHOOK_URL],
        smtp_password=SMTP_PASSWORD,
    )

    rendered = repr(settings) + json.dumps(describe_settings(settings))

    for secret in SECRETS:
        assert secret not in rendered, f"{secret} leaked into repr() or --check-config"
    # The channel names stay visible: the summary must remain useful.
    assert "telegram" in rendered
    assert "slack" in rendered
