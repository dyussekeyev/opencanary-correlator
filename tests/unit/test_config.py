"""Tests for pydantic-settings based configuration and the legacy importer."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from opencanary_correlator.config import DEFAULT_HEALTH_HOST, DEFAULT_HEALTH_PORT, Settings

PROJECT_ROOT = Path(__file__).resolve().parents[2]
TEST_REDIS_URL = "redis://localhost:6379/0"


def test_redis_url_is_required(monkeypatch: Any) -> None:
    monkeypatch.delenv("OCC_REDIS_URL", raising=False)

    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_alert_detail_defaults_favour_readable_chat_messages(settings_factory: Any) -> None:
    settings = settings_factory()

    assert settings.telegram_detail == "standard"
    assert settings.slack_detail == "standard"
    assert settings.discord_detail == "standard"
    # Legacy text stays the default where a parser or mail filter may depend on it.
    assert settings.webhook_detail == "minimal"
    assert settings.smtp_detail == "minimal"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("detailed", "detailed"),
        ("DETAILED", "detailed"),
        (" Standard ", "standard"),
        ("minimal", "minimal"),
        ("brief", "minimal"),
        ("short", "minimal"),
        ("full", "detailed"),
        ("verbose", "detailed"),
    ],
)
def test_alert_detail_is_normalised(settings_factory: Any, raw: str, expected: str) -> None:
    settings = settings_factory(telegram_detail=raw)

    assert settings.telegram_detail == expected


@pytest.mark.parametrize("value", ["loud", "", "standard-ish"])
def test_unknown_alert_detail_is_rejected(settings_factory: Any, value: str) -> None:
    with pytest.raises(ValidationError):
        settings_factory(discord_detail=value)


def test_alert_detail_is_read_from_the_environment(monkeypatch: Any) -> None:
    monkeypatch.setenv("OCC_REDIS_URL", TEST_REDIS_URL)
    monkeypatch.setenv("OCC_TELEGRAM_DETAIL", "detailed")
    monkeypatch.setenv("OCC_WEBHOOK_DETAIL", "full")

    settings = Settings(_env_file=None)

    assert settings.telegram_detail == "detailed"
    assert settings.webhook_detail == "detailed"


def test_reads_values_from_environment(monkeypatch: Any) -> None:
    monkeypatch.setenv("OCC_REDIS_URL", "rediss://redis.example:6380/1")
    monkeypatch.setenv("OCC_TCP_PORT", "1515")
    monkeypatch.setenv("OCC_LOG_LEVEL", "debug")
    monkeypatch.setenv("OCC_WEBHOOK_URLS", "https://siem.example/hook,https://backup.example/hook")

    settings = Settings(_env_file=None)

    assert settings.redis_url == "rediss://redis.example:6380/1"
    assert settings.tcp_port == 1515
    assert settings.log_level == "DEBUG"
    assert settings.webhook_urls == ["https://siem.example/hook", "https://backup.example/hook"]


def test_log_file_defaults_to_stderr_only(settings_factory: Any) -> None:
    assert settings_factory().log_file is None
    assert settings_factory(log_file="   ").log_file is None


def test_log_file_reads_the_environment(monkeypatch: Any) -> None:
    monkeypatch.setenv("OCC_REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setenv("OCC_LOG_FILE", "/var/log/opencanary-correlator/correlator.log")

    settings = Settings(_env_file=None)

    assert settings.log_file == "/var/log/opencanary-correlator/correlator.log"


def test_log_level_accepts_the_warn_alias(monkeypatch: Any) -> None:
    monkeypatch.setenv("OCC_REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setenv("OCC_LOG_LEVEL", "warn")

    assert Settings(_env_file=None).log_level == "WARNING"


def test_accepts_json_encoded_lists(settings_factory: Any) -> None:
    settings = settings_factory(slack_webhooks='["https://hooks.slack.com/services/a"]')

    assert settings.slack_webhooks == ["https://hooks.slack.com/services/a"]


def test_empty_comma_separated_values_become_empty_lists(settings_factory: Any) -> None:
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
        pytest.param({"webhook_urls": ["http://siem.example/hook"]}, id="webhook-plain-http"),
        pytest.param({"slack_webhooks": ["http://hooks.example/x"]}, id="slack-plain-http"),
        pytest.param({"discord_webhooks": ["http://discord.example/x"]}, id="discord-plain-http"),
        pytest.param({"telegram_token": "no-colon-token"}, id="telegram-bad-token"),
        pytest.param({"telegram_token": "abc:secret"}, id="telegram-non-numeric-bot-id"),
        pytest.param({"smtp_from": "not-an-address"}, id="bad-sender"),
        pytest.param({"max_line_bytes": 10}, id="line-limit-too-small"),
        pytest.param({"event_concurrency": 0}, id="no-consumer-lanes"),
        pytest.param({"event_concurrency": 65}, id="too-many-lanes"),
    ],
)
def test_invalid_settings_are_rejected(settings_factory: Any, overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        settings_factory(**overrides)


def test_loopback_webhooks_may_use_plain_http(settings_factory: Any) -> None:
    settings = settings_factory(webhook_urls=["http://127.0.0.1:9000/hook"])

    assert settings.webhook_urls == ["http://127.0.0.1:9000/hook"]


def test_valid_telegram_token_is_accepted(settings_factory: Any) -> None:
    settings = settings_factory(telegram_token="123456:AA-bb_cc")

    assert settings.telegram_token is not None
    assert settings.telegram_token.get_secret_value() == "123456:AA-bb_cc"


def test_event_concurrency_defaults_to_eight_lanes(settings_factory: Any) -> None:
    assert settings_factory().event_concurrency == 8
    assert settings_factory(event_concurrency=1).event_concurrency == 1


def test_secrets_never_appear_in_repr(settings_factory: Any) -> None:
    settings = settings_factory(
        telegram_token="123456:telegram-secret",
        smtp_password="smtp-secret",
    )
    rendered = repr(settings)

    assert "telegram-secret" not in rendered
    assert "smtp-secret" not in rendered
    assert settings.telegram_token is not None
    assert settings.telegram_token.get_secret_value() == "123456:telegram-secret"


def _declared_setting(line: str) -> str | None:
    """Return the setting named on an `OCC_...=` line, commented or not.

    An optional setting has to be documented in a comment: `OCC_LOG_FILE=` and
    "the line is absent" are not the same thing, because the compose file uses
    `${OCC_LOG_FILE-default}` and only an empty value opts out of the volume.
    """
    stripped = line.strip().removeprefix("#").strip()
    if not stripped.startswith("OCC_") or "=" not in stripped:
        return None
    return stripped.split("=", 1)[0].removeprefix("OCC_").lower()


def test_env_example_documents_every_setting() -> None:
    fields = set(Settings.model_fields)
    documented = {
        name
        for line in (PROJECT_ROOT / ".env.example").read_text(encoding="utf-8").splitlines()
        if (name := _declared_setting(line)) in fields
    }

    assert documented == fields


def test_per_incident_horizons_are_read_from_the_environment(monkeypatch: Any) -> None:
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
def test_invalid_incident_horizons_are_rejected(settings_factory: Any, value: Any) -> None:
    with pytest.raises(ValidationError):
        settings_factory(incident_horizons=value)


@pytest.mark.parametrize("value", [0, "0", "00", "+0", ""])
def test_health_port_zero_or_empty_disables_the_endpoint(settings_factory: Any, value: Any) -> None:
    settings = settings_factory(health_port=value)

    assert settings.health_port is None


def test_health_port_default_avoids_the_emulated_http_port(settings_factory: Any) -> None:
    assert settings_factory().health_port == DEFAULT_HEALTH_PORT
    assert DEFAULT_HEALTH_PORT != 8080


def test_enrichment_is_off_until_it_is_configured(settings_factory: Any) -> None:
    settings = settings_factory()

    assert settings.geoip_city_db is None
    assert settings.geoip_asn_db is None
    assert settings.virustotal_api_key is None
    # The published free-tier ceilings are the defaults.
    assert (settings.virustotal_per_minute, settings.virustotal_per_day) == (4, 500)
    assert settings.virustotal_per_month == 15_500


def test_the_virustotal_key_stays_out_of_repr(settings_factory: Any) -> None:
    settings = settings_factory(virustotal_api_key="vt-secret-value")

    assert "vt-secret-value" not in repr(settings)
    assert settings.virustotal_api_key is not None


def test_slack_is_disabled_until_it_has_a_webhook(settings_factory: Any) -> None:
    """`enabled` with no endpoint is a dead switch, not a working channel."""
    assert settings_factory().slack_enabled is False
    only_webhook = settings_factory(slack_webhooks="https://hooks.slack.com/services/a")
    assert only_webhook.slack_enabled is False


def test_enabling_slack_without_a_webhook_fails_at_startup(settings_factory: Any) -> None:
    with pytest.raises(ValidationError, match="slack_webhooks"):
        settings_factory(slack_enabled=True)


def test_enabling_slack_with_a_webhook_is_accepted(settings_factory: Any) -> None:
    settings = settings_factory(
        slack_enabled=True, slack_webhooks="https://hooks.slack.com/services/a"
    )

    assert settings.slack_enabled is True


def test_intake_defaults_to_loopback_and_uncommon_ports(settings_factory: Any) -> None:
    """The common deployment is one host, and honeypot traps own the common ports."""
    settings = settings_factory()

    assert settings.tcp_host == "127.0.0.1"
    assert settings.syslog_host == "127.0.0.1"
    assert (settings.tcp_port, settings.syslog_port) == (15140, 15141)
    assert settings.tcp_port not in {21, 22, 23, 25, 80, 443, 8080, 8443}


def test_health_port_reads_a_custom_value_from_the_environment(monkeypatch: Any) -> None:
    monkeypatch.setenv("OCC_REDIS_URL", TEST_REDIS_URL)
    monkeypatch.setenv("OCC_HEALTH_PORT", "9090")

    assert Settings(_env_file=None).health_port == 9090


@pytest.mark.parametrize("value", ["0", "00", " 0 ", ""])
def test_health_port_disabled_from_the_environment(monkeypatch: Any, value: str) -> None:
    monkeypatch.setenv("OCC_REDIS_URL", TEST_REDIS_URL)
    monkeypatch.setenv("OCC_HEALTH_PORT", value)

    assert Settings(_env_file=None).health_port is None


def test_health_allowed_ips_default_to_loopback(settings_factory: Any) -> None:
    assert settings_factory().health_allowed_ips == ["127.0.0.1/32", "::1/128"]


@pytest.mark.parametrize("value", ["", "   "])
def test_empty_health_allowed_ips_fall_back_to_loopback(settings_factory: Any, value: str) -> None:
    assert settings_factory(health_allowed_ips=value).health_allowed_ips == [
        "127.0.0.1/32",
        "::1/128",
    ]


def test_health_allowed_ips_reads_from_the_environment(monkeypatch: Any) -> None:
    monkeypatch.setenv("OCC_REDIS_URL", TEST_REDIS_URL)
    monkeypatch.setenv("OCC_HEALTH_ALLOWED_IPS", "10.0.0.0/8, 192.0.2.7")

    assert Settings(_env_file=None).health_allowed_ips == ["10.0.0.0/8", "192.0.2.7"]


@pytest.mark.parametrize("value", ["10.0.0.0/33", "not-an-address"])
def test_invalid_health_allowed_ips_are_rejected(settings_factory: Any, value: str) -> None:
    with pytest.raises(ValidationError):
        settings_factory(health_allowed_ips=value)


def test_health_host_defaults_to_all_interfaces(settings_factory: Any) -> None:
    assert settings_factory().health_host == DEFAULT_HEALTH_HOST


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "localhost"])
def test_health_host_reads_a_custom_value_from_the_environment(monkeypatch: Any, host: str) -> None:
    monkeypatch.setenv("OCC_REDIS_URL", TEST_REDIS_URL)
    monkeypatch.setenv("OCC_HEALTH_HOST", f"  {host}  ")

    assert Settings(_env_file=None).health_host == host


@pytest.mark.parametrize("value", ["", "   "])
def test_blank_health_host_binds_every_interface(monkeypatch: Any, value: str) -> None:
    monkeypatch.setenv("OCC_REDIS_URL", TEST_REDIS_URL)
    monkeypatch.setenv("OCC_HEALTH_HOST", value)

    assert Settings(_env_file=None).health_host == DEFAULT_HEALTH_HOST


def test_empty_incident_horizons_are_allowed(settings_factory: Any) -> None:
    settings = settings_factory(incident_horizons={})

    assert settings.incident_horizons == {}
    assert settings.horizon_for("ftp.login_attempt") == settings.incident_horizon


def test_smtp_tls_modes_are_mutually_exclusive(settings_factory: Any) -> None:
    settings = settings_factory(smtp_starttls=False, smtp_use_tls=True)

    assert settings.smtp_use_tls is True
    assert settings.smtp_starttls is False

    with pytest.raises(ValidationError):
        settings_factory(smtp_starttls=True, smtp_use_tls=True)


def test_legacy_enable_flags_disable_notification_channels(tmp_path: Path) -> None:
    legacy = {
        "console.email_notification_enable": False,
        "console.email_notification_address": ["soc@example.com"],
        "console.email_host": "smtp.example.com",
        "console.slack_notification_enable": False,
        "console.slack_notification_webhook": ["https://hooks.slack.com/services/x"],
        "console.sms_notification_enable": True,
    }
    path = tmp_path / "legacy.conf"
    path.write_text(json.dumps(legacy), encoding="utf-8")

    settings = Settings.from_legacy_json(path, overrides={"redis_url": TEST_REDIS_URL})

    assert settings.smtp_enabled is False
    assert settings.slack_enabled is False
    # The addresses stay available for inspection/overrides, but the channels
    # must not be instantiated while their legacy enable flag is false.
    assert settings.smtp_to == ["soc@example.com"]
    assert settings.slack_webhooks == ["https://hooks.slack.com/services/x"]
    assert not hasattr(settings, "twilio_sid")


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
    # These keys were absent in the legacy file, and the old notifier treated
    # them as disabled rather than inferring them from the configured endpoints.
    assert settings.smtp_enabled is False
    assert settings.slack_enabled is False
    assert not hasattr(settings, "mandrill_key")
    assert not hasattr(settings, "twilio_sid")


def test_legacy_importer_logs_dropped_keys(tmp_path: Path, caplog: Any) -> None:
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


def test_max_stored_events_defaults_to_the_console_limit(settings_factory: Any) -> None:
    assert settings_factory().max_stored_events == 100


@pytest.mark.parametrize("value", [0, -1, 10_001])
def test_max_stored_events_is_bounded(settings_factory: Any, value: Any) -> None:
    with pytest.raises(ValidationError):
        settings_factory(max_stored_events=value)


def test_max_stored_events_can_be_raised_from_the_environment(monkeypatch: Any) -> None:
    monkeypatch.setenv("OCC_REDIS_URL", TEST_REDIS_URL)
    monkeypatch.setenv("OCC_MAX_STORED_EVENTS", "500")

    assert Settings(_env_file=None).max_stored_events == 500


def test_lookup_scan_limit_defaults_to_a_bounded_window(settings_factory: Any) -> None:
    assert settings_factory().incident_lookup_scan_limit == 100


@pytest.mark.parametrize("value", [0, -1, 10_001])
def test_lookup_scan_limit_is_bounded(settings_factory: Any, value: Any) -> None:
    with pytest.raises(ValidationError):
        settings_factory(incident_lookup_scan_limit=value)


def test_lookup_scan_limit_can_be_raised_from_the_environment(monkeypatch: Any) -> None:
    monkeypatch.setenv("OCC_REDIS_URL", TEST_REDIS_URL)
    monkeypatch.setenv("OCC_INCIDENT_LOOKUP_SCAN_LIMIT", "500")

    assert Settings(_env_file=None).incident_lookup_scan_limit == 500
