"""`--check-config`: the secret-free summary of the effective configuration."""

from __future__ import annotations

import json
from typing import Any

from opencanary_correlator.app.describe import channel_names, safe_redis_url
from opencanary_correlator.app.runner import main


def test_safe_redis_url_masks_the_password() -> None:
    masked = safe_redis_url("redis://user:supersecret@redis.example:6380/1")

    assert "supersecret" not in masked
    assert masked == "redis://user:***@redis.example:6380/1"


def test_check_config_prints_redacted_summary(monkeypatch: Any, capsys: Any) -> None:
    monkeypatch.setenv("OCC_REDIS_URL", "redis://user:supersecret@redis.example:6379/0")
    monkeypatch.setenv("OCC_SLACK_WEBHOOKS", "https://hooks.slack.test/x")
    monkeypatch.setenv("OCC_SLACK_ENABLED", "true")

    code = main(["--check-config"])

    captured = capsys.readouterr()
    assert code == 0
    assert "supersecret" not in captured.out
    assert "***" in captured.out
    payload = json.loads(captured.out)
    assert payload["channels"] == ["slack"]


def test_check_config_accepts_env_health_port_zero(monkeypatch: Any, capsys: Any) -> None:
    monkeypatch.setenv("OCC_REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setenv("OCC_HEALTH_PORT", "0")

    code = main(["--check-config"])

    captured = capsys.readouterr()
    assert code == 0, captured.err
    assert json.loads(captured.out)["health_port"] is None


def test_check_config_cli_health_port_zero_overrides_the_env(monkeypatch: Any, capsys: Any) -> None:
    monkeypatch.setenv("OCC_REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setenv("OCC_HEALTH_PORT", "9090")

    code = main(["--check-config", "--health-port", "0"])

    captured = capsys.readouterr()
    assert code == 0, captured.err
    assert json.loads(captured.out)["health_port"] is None


def test_check_config_reports_the_configured_health_host(monkeypatch: Any, capsys: Any) -> None:
    monkeypatch.setenv("OCC_REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setenv("OCC_HEALTH_HOST", "127.0.0.1")

    code = main(["--check-config"])

    captured = capsys.readouterr()
    assert code == 0, captured.err
    assert json.loads(captured.out)["health_host"] == "127.0.0.1"


def test_check_config_reports_enrichment(monkeypatch: Any, capsys: Any) -> None:
    monkeypatch.setenv("OCC_REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setenv("OCC_GEOIP_CITY_DB", "/data/geoip/city.mmdb")
    monkeypatch.setenv("OCC_VIRUSTOTAL_API_KEY", "1:key")

    assert main(["--check-config"]) == 0

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["enrichment"] == {"geoip": True, "virustotal": True}
    assert "1:key" not in captured.out


def test_check_config_reports_the_log_file(monkeypatch: Any, capsys: Any, tmp_path: Any) -> None:
    monkeypatch.setenv("OCC_REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setenv("OCC_LOG_FILE", str(tmp_path / "correlator.log"))

    code = main(["--check-config"])

    assert code == 0
    assert json.loads(capsys.readouterr().out)["log_file"].endswith("correlator.log")


def test_channel_names_counts_every_telegram_chat(settings_factory: Any) -> None:
    settings = settings_factory(
        telegram_token="123:abc",
        telegram_chat_ids=["-1001", "-1002"],
        smtp_enabled=True,
        smtp_host="smtp.example",
        smtp_to=["ops@example"],
    )

    assert channel_names(settings) == ["telegram", "telegram", "smtp"]


def test_channel_names_skips_smtp_without_a_recipient(settings_factory: Any) -> None:
    settings = settings_factory(smtp_enabled=True, smtp_host="smtp.example", smtp_to=[])

    assert channel_names(settings) == []
