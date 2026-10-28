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
#: Sent as a header, so `httpx` never logs the URL with it — the filter covers
#: the paths that are not visible from here (an exception carrying the request).
VIRUSTOTAL_KEY = "VT-API-SECRET-KEY"

SECRETS = (
    TELEGRAM_TOKEN,
    "TELEGRAM-SECRET",
    "SLACK-SECRET",
    "DISCORD-SECRET",
    "ARBITRARY-SECRET",
    SMTP_PASSWORD,
    CAPTURED_PASSWORD,
    VIRUSTOTAL_KEY,
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
        virustotal_api_key=VIRUSTOTAL_KEY,
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

    # `NOISY_LOGGERS` caps httpx/httpcore at WARNING, so their request lines are
    # not written at all: the endpoints never appear, masked or otherwise.
    for marker in ("api.telegram.org", "hooks.slack.com", "discord.com", "siem.example"):
        assert marker not in log_text, f"{marker} reached the log file"
    # The alert shows the log entry with the credential masked, not dropped.
    assert "PASSWORD=***" in outbound


def test_no_secret_reaches_repr_or_check_config(settings_factory: Any) -> None:
    settings = settings_factory(
        telegram_token=TELEGRAM_TOKEN,
        slack_webhooks=[SLACK_URL],
        discord_webhooks=[DISCORD_URL],
        webhook_urls=[WEBHOOK_URL],
        smtp_password=SMTP_PASSWORD,
        virustotal_api_key=VIRUSTOTAL_KEY,
    )

    rendered = repr(settings) + json.dumps(describe_settings(settings))

    for secret in SECRETS:
        assert secret not in rendered, f"{secret} leaked into repr() or --check-config"
    # The channel names stay visible: the summary must remain useful.
    assert "telegram" in rendered
    assert "slack" in rendered


def test_a_logged_virustotal_key_is_masked(
    settings_factory: Any, tmp_path: Any, capsys: Any
) -> None:
    """The key reaches no sink even when a library echoes it.

    `httpx` logs the request line, not the headers, so today nothing prints the
    key on its own. This drives the same log pipeline a future one would, which
    is the only way to prove the value is in the filter's list.
    """
    import logging

    settings = settings_factory(virustotal_api_key=VIRUSTOTAL_KEY)
    target = tmp_path / "correlator.log"
    configure_logging(settings.log_level, target, secrets=log_secrets(settings))

    logging.getLogger("opencanary_correlator.enrichment.virustotal").warning(
        "request headers: {'x-apikey': '%s'}", VIRUSTOTAL_KEY
    )

    log_text = target.read_text(encoding="utf-8")
    stderr = capsys.readouterr().err
    assert VIRUSTOTAL_KEY not in log_text
    assert VIRUSTOTAL_KEY not in stderr
    assert "x-apikey" in log_text
