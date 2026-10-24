"""Tests for pydantic-settings based configuration and the legacy importer."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest
from pydantic import ValidationError

from opencanary_correlator.config import Settings

PROJECT_ROOT = Path(__file__).resolve().parents[2]
TEST_REDIS_URL = "redis://localhost:6379/0"


def test_redis_url_is_required(monkeypatch) -> None:
    monkeypatch.delenv("OCC_REDIS_URL", raising=False)

    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_reads_values_from_environment(monkeypatch) -> None:
    monkeypatch.setenv("OCC_REDIS_URL", "rediss://redis.example:6380/1")
    monkeypatch.setenv("OCC_TCP_PORT", "1515")
    monkeypatch.setenv("OCC_LOG_LEVEL", "debug")
    monkeypatch.setenv("OCC_WEBHOOK_URLS", "https://siem.example/hook,https://backup.example/hook")

    settings = Settings(_env_file=None)

    assert settings.redis_url == "rediss://redis.example:6380/1"
    assert settings.tcp_port == 1515
    assert settings.log_level == "DEBUG"
    assert settings.webhook_urls == ["https://siem.example/hook", "https://backup.example/hook"]


def test_accepts_json_encoded_lists(settings_factory) -> None:
    settings = settings_factory(slack_webhooks='["https://hooks.slack.com/services/a"]')

    assert settings.slack_webhooks == ["https://hooks.slack.com/services/a"]


def test_empty_comma_separated_values_become_empty_lists(settings_factory) -> None:
    settings = settings_factory(discord_webhooks="", smtp_to="   ")

    assert settings.discord_webhooks == []
    assert settings.smtp_to == []


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({"redis_url": "http://localhost:6379/0"}, id="bad-redis-scheme"),
        pytest.param({"tcp_port": 0}, id="port-zero"),
        pytest.param({"tcp_port": 70000}, id="port-too-large"),
        pytest.param({"webhook_urls": ["ftp://siem.example"]}, id="webhook-not-http"),
        pytest.param({"smtp_from": "not-an-address"}, id="bad-sender"),
        pytest.param({"max_line_bytes": 10}, id="line-limit-too-small"),
    ],
)
def test_invalid_settings_are_rejected(settings_factory, overrides: dict) -> None:
    with pytest.raises(ValidationError):
        settings_factory(**overrides)


def test_secrets_never_appear_in_repr(settings_factory) -> None:
    settings = settings_factory(
        telegram_token="123456:telegram-secret",
        smtp_password="smtp-secret",
    )
    rendered = repr(settings)

    assert "telegram-secret" not in rendered
    assert "smtp-secret" not in rendered
    assert settings.telegram_token is not None
    assert settings.telegram_token.get_secret_value() == "123456:telegram-secret"


def test_env_example_documents_every_setting() -> None:
    documented = {
        line.split("=", 1)[0].removeprefix("OCC_").lower()
        for line in (PROJECT_ROOT / ".env.example").read_text(encoding="utf-8").splitlines()
        if line.startswith("OCC_")
    }

    assert documented == set(Settings.model_fields)


def test_per_incident_horizons_are_read_from_the_environment(monkeypatch) -> None:
    monkeypatch.setenv("OCC_REDIS_URL", TEST_REDIS_URL)
    monkeypatch.setenv("OCC_INCIDENT_HORIZON", "60")
    monkeypatch.setenv(
        "OCC_INCIDENT_HORIZONS",
        '{"ftp.login_attempt": 300, "scans.network_portscan": 1800}',
    )

    settings = Settings(_env_file=None)

    assert settings.horizon_for("ftp.login_attempt") == 300.0
    assert settings.horizon_for("scans.network_portscan") == 1800.0
    assert settings.horizon_for("ssh.login_attempt") == 60.0


@pytest.mark.parametrize(
    "value",
    [
        pytest.param({"ftp.logon": 10}, id="unknown-incident"),
        pytest.param({"ftp.login_attempt": -1}, id="negative"),
        pytest.param({"ftp.login_attempt": float("inf")}, id="infinite"),
        pytest.param("not-json", id="malformed-json"),
    ],
)
def test_invalid_incident_horizons_are_rejected(settings_factory, value) -> None:
    with pytest.raises(ValidationError):
        settings_factory(incident_horizons=value)


def test_empty_incident_horizons_are_allowed(settings_factory) -> None:
    settings = settings_factory(incident_horizons={})

    assert settings.incident_horizons == {}
    assert settings.horizon_for("ftp.login_attempt") == settings.incident_horizon


def test_legacy_json_is_imported(tmp_path: Path) -> None:
    legacy = {
        "console.incident_horizon": 30,
        "ftp.incident_horizon": 300,
        "httproxy.incident_horizon": 45,
        "smb.file_open_horizon": 120,
        "scans.host_portscan_horizon": 90,
        "scans.network_portscan_horizon": 1800,
        "portscan.packet_threshold": 7,
        "portscan.monitor_period": 90,
        "networkscan.packet_threshold": 3,
        "networkscan.monitor_period": 7200,
        "console.email_notification_address": ["soc@example.com"],
        "console.email_host": "smtp.example.com",
        "console.email_port": 2525,
        "console.slack_notification_webhook": ["https://hooks.slack.com/services/x"],
        "console.mandrill_key": "do-not-migrate",
        "twilio.sid": "AC00000000000000000000000000000000",
        "twilio.auth_token": "do-not-migrate-either",
    }
    path = tmp_path / "opencanary_correlator.conf"
    path.write_text(json.dumps(legacy), encoding="utf-8")

    settings = Settings.from_legacy_json(path, overrides={"redis_url": TEST_REDIS_URL})

    assert settings.incident_horizon == 30.0
    assert settings.incident_horizons == {
        "ftp.login_attempt": 300.0,
        "httpproxy.login_attempt": 45.0,
        "smb.file_open": 120.0,
        "scans.host_portscan": 90.0,
        "scans.network_portscan": 1800.0,
    }
    assert settings.horizon_for("ftp.login_attempt") == 300.0
    assert settings.horizon_for("ssh.login_attempt") == 30.0
    assert settings.scan_host_threshold == 7
    assert settings.scan_host_horizon == 90.0
    assert settings.scan_network_threshold == 3
    assert settings.scan_network_horizon == 7200.0
    assert settings.smtp_to == ["soc@example.com"]
    assert settings.smtp_host == "smtp.example.com"
    assert settings.smtp_port == 2525
    assert settings.slack_webhooks == ["https://hooks.slack.com/services/x"]
    assert not hasattr(settings, "mandrill_key")
    assert not hasattr(settings, "twilio_sid")


def test_legacy_importer_logs_dropped_keys(tmp_path: Path, caplog) -> None:
    path = tmp_path / "legacy.conf"
    path.write_text(json.dumps({"twilio.sid": "AC123", "unknown.key": 1}), encoding="utf-8")
    caplog.set_level(logging.INFO, logger="opencanary_correlator.config")

    Settings.from_legacy_json(path, overrides={"redis_url": TEST_REDIS_URL})

    assert "twilio.sid" in caplog.text
    assert "unknown.key" in caplog.text


def test_legacy_values_can_be_overridden_by_explicit_arguments(tmp_path: Path) -> None:
    path = tmp_path / "legacy.conf"
    path.write_text(json.dumps({"console.incident_horizon": 30}), encoding="utf-8")

    settings = Settings.from_legacy_json(
        path,
        overrides={"redis_url": TEST_REDIS_URL, "incident_horizon": 5},
    )

    assert settings.incident_horizon == 5.0
