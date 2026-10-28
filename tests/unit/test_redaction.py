"""URL-embedded secret redaction used by the log pipeline."""

from __future__ import annotations

import pytest

from opencanary_correlator.redaction import redact_url_secrets, sanitize_text

TELEGRAM_URL = "https://api.telegram.org/bot123456:AAH-super_secret/sendMessage"


def test_telegram_bot_token_is_masked() -> None:
    line = f'HTTP Request: POST {TELEGRAM_URL} "HTTP/1.1 200 OK"'

    redacted = redact_url_secrets(line)

    assert "AAH-super_secret" not in redacted
    assert "123456" not in redacted
    assert "https://api.telegram.org/bot***/sendMessage" in redacted
    assert "HTTP Request: POST" in redacted


#: Assembled from parts on purpose: a literal shaped like a real Slack webhook
#: is blocked by GitHub push protection even when every character is a placeholder.
SLACK_WEBHOOK = "https://hooks.slack.com" + "/services/T00000000/B00000000/PLACEHOLDER"
DISCORD_WEBHOOK = "https://discord.com/api/webhooks" + "/123456789/PLACEHOLDER"
DISCORD_APP_WEBHOOK = "https://discordapp.com/api/webhooks" + "/123456789/PLACEHOLDER"


@pytest.mark.parametrize("url", [SLACK_WEBHOOK, DISCORD_WEBHOOK, DISCORD_APP_WEBHOOK])
def test_webhook_paths_are_masked(url: str) -> None:
    redacted = redact_url_secrets(f"POST {url} 204")

    assert "PLACEHOLDER" not in redacted
    assert redacted.endswith(" 204")


@pytest.mark.parametrize(
    "url",
    [
        "redis://:hunter2@redis:6379/0",
        "redis://default:hunter2@redis:6379/0",
        "rediss://user:hunter2@redis.example:6380/1",
    ],
)
def test_url_passwords_are_masked(url: str) -> None:
    redacted = redact_url_secrets(f"cannot connect to {url}")

    assert "hunter2" not in redacted
    assert "***@" in redacted


@pytest.mark.parametrize(
    "query",
    [
        "token=abc123",
        "access_token=abc123",
        "api_key=abc123",
        "key=abc123",
        "secret=abc123",
        "signature=abc123",
        "auth=abc123",
    ],
)
def test_query_string_secrets_are_masked(query: str) -> None:
    line = f"POST https://siem.example/hook?{query}&kind=alert 200"

    redacted = redact_url_secrets(line)

    assert "abc123" not in redacted
    assert "***" in redacted
    assert "kind=alert" in redacted


def test_a_parameter_that_only_starts_like_a_secret_is_kept() -> None:
    line = "POST https://siem.example/hook?author=bob 200"

    assert redact_url_secrets(line) == line


def test_unicode_line_separators_are_flattened() -> None:
    text = sanitize_text("a\u2028b\u0085c\u2029d")

    assert "\u2028" not in text
    assert "\u0085" not in text
    assert "\u2029" not in text
    assert len(text.splitlines()) == 1


def test_ordinary_text_is_untouched() -> None:
    line = "alert_dispatch error dispatcher=telegram incident=incident:ssh:10.0.0.5:1700000000"

    assert redact_url_secrets(line) == line


def test_public_urls_are_kept() -> None:
    line = "GET https://example.com/status 200"

    assert redact_url_secrets(line) == line
