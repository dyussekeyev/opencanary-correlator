"""Wiring: which channels, enrichers and listeners the settings produce."""

from __future__ import annotations

import asyncio
import logging
from typing import Any, cast

import pytest

from opencanary_correlator.app.channels import build_dispatchers, channel_names
from opencanary_correlator.app.parser import CorrelatorStartupError
from opencanary_correlator.app.wiring import build_enricher, build_receivers


async def test_build_dispatchers_follows_settings(settings_factory: Any, store: Any) -> None:
    settings = settings_factory(
        webhook_urls=["https://siem.test/hook"],
        slack_enabled=True,
        slack_webhooks=["https://hooks.slack.test/x"],
        discord_webhooks=["https://discord.test/webhook"],
        telegram_token="1:token",
        telegram_chat_ids=["1", "2"],
        smtp_host="smtp.test",
        smtp_to=["soc@example.test"],
    )

    dispatchers = build_dispatchers(settings, store)
    try:
        assert [dispatcher.name for dispatcher in dispatchers] == [
            "webhook",
            "slack",
            "discord",
            "telegram",
            "telegram",
            "smtp",
        ]
    finally:
        await asyncio.gather(*(dispatcher.aclose() for dispatcher in dispatchers))


async def test_the_description_and_the_build_agree(settings_factory: Any, store: Any) -> None:
    """One channel table backs both, so a summary cannot promise what is not built."""
    settings = settings_factory(
        webhook_urls=["https://siem.test/a", "https://siem.test/b"],
        slack_enabled=True,
        slack_webhooks=["https://hooks.slack.test/x"],
        discord_webhooks=["https://discord.test/webhook"],
        telegram_token="1:token",
        telegram_chat_ids=["1", "2"],
        smtp_host="smtp.test",
        smtp_to=["soc@example.test"],
    )

    dispatchers = build_dispatchers(settings, store)
    try:
        assert [dispatcher.name for dispatcher in dispatchers] == channel_names(settings)
    finally:
        await asyncio.gather(*(dispatcher.aclose() for dispatcher in dispatchers))


def test_no_enrichment_is_built_without_configuration(
    settings_factory: Any, store: Any, audit: Any
) -> None:
    assert build_enricher(settings_factory(), store, audit) is None


def test_a_missing_geo_database_stops_startup(
    settings_factory: Any, store: Any, audit: Any, tmp_path: Any
) -> None:
    settings = settings_factory(geoip_city_db=str(tmp_path / "absent.mmdb"))

    with pytest.raises(CorrelatorStartupError, match="geoip database"):
        build_enricher(settings, store, audit)


async def test_a_virustotal_key_builds_the_enricher(
    settings_factory: Any, store: Any, audit: Any
) -> None:
    settings = settings_factory(virustotal_api_key="1:key")

    enricher = build_enricher(settings, store, audit)

    assert enricher is not None
    assert enricher.enabled is True
    await enricher.aclose()


async def test_build_dispatchers_passes_the_configured_detail(
    settings_factory: Any, store: Any, monkeypatch: Any
) -> None:
    captured: dict[str, Any] = {}

    class RecordingTelegram:
        def __init__(self, **kwargs: Any) -> None:
            captured.update(kwargs)

    monkeypatch.setattr("opencanary_correlator.app.channels.TelegramDispatcher", RecordingTelegram)
    settings = settings_factory(
        telegram_detail="detailed",
        telegram_token="1:token",
        telegram_chat_ids=["1"],
    )

    dispatchers = build_dispatchers(settings, store)

    assert len(dispatchers) == 1
    assert captured["detail"] == "detailed"


async def test_build_dispatchers_defaults_to_the_standard_detail(
    settings_factory: Any, store: Any, monkeypatch: Any
) -> None:
    captured: dict[str, Any] = {}

    class RecordingTelegram:
        def __init__(self, **kwargs: Any) -> None:
            captured.update(kwargs)

    monkeypatch.setattr("opencanary_correlator.app.channels.TelegramDispatcher", RecordingTelegram)
    settings = settings_factory(telegram_token="1:token", telegram_chat_ids=["1"])

    dispatchers = build_dispatchers(settings, store)

    assert len(dispatchers) == 1
    assert captured["detail"] == "standard"


async def test_build_dispatchers_respects_disabled_channels(
    settings_factory: Any, store: Any
) -> None:
    settings = settings_factory(
        slack_enabled=False,
        slack_webhooks=["https://hooks.slack.test/x"],
        smtp_enabled=False,
        smtp_host="smtp.test",
        smtp_to=["soc@example.test"],
    )

    assert build_dispatchers(settings, store) == []
    assert channel_names(settings) == []


async def test_a_slack_webhook_with_the_switch_off_is_reported(
    settings_factory: Any, store: Any, caplog: Any
) -> None:
    """The mirror image of the startup error: configured, but silently off."""
    settings = settings_factory(slack_webhooks=["https://hooks.slack.test/x"])

    with caplog.at_level(logging.WARNING):
        dispatchers = build_dispatchers(settings, store)

    assert dispatchers == []
    assert "OCC_SLACK_ENABLED is false" in caplog.text


async def test_build_dispatchers_passes_implicit_tls_to_smtp(
    settings_factory: Any, store: Any, monkeypatch: Any
) -> None:
    captured: dict[str, Any] = {}

    class RecordingSmtp:
        def __init__(self, **kwargs: Any) -> None:
            captured.update(kwargs)

    monkeypatch.setattr("opencanary_correlator.app.channels.SmtpDispatcher", RecordingSmtp)
    settings = settings_factory(
        smtp_host="smtp.test",
        smtp_to=["soc@example.test"],
        smtp_starttls=False,
        smtp_use_tls=True,
    )

    dispatchers = build_dispatchers(settings, store)

    assert len(dispatchers) == 1
    assert captured["start_tls"] is False
    assert captured["use_tls"] is True


async def test_build_dispatchers_scopes_breakers_to_each_endpoint(
    settings_factory: Any, store: Any, monkeypatch: Any
) -> None:
    names: list[str] = []

    class RecordingBreaker:
        def __init__(self, _store: Any, name: str) -> None:
            names.append(name)

    monkeypatch.setattr("opencanary_correlator.app.channels.CircuitBreaker", RecordingBreaker)
    settings = settings_factory(
        webhook_urls=["https://siem.test/a", "https://siem.test/b"],
        slack_enabled=True,
        slack_webhooks=["https://slack.test/a", "https://slack.test/b"],
        discord_webhooks=["https://discord.test/a", "https://discord.test/b"],
        telegram_token="1:token",
        telegram_chat_ids=["1", "2"],
    )

    dispatchers = build_dispatchers(settings, store)
    try:
        assert [name.split(":", 1)[0] for name in names] == [
            "webhook",
            "webhook",
            "slack",
            "slack",
            "discord",
            "discord",
            "telegram",
            "telegram",
        ]
        assert len(set(names)) == len(names)
        assert not any(
            marker in name
            for name in names
            for marker in ("siem.test", "slack.test", "discord.test")
        )
    finally:
        await asyncio.gather(*(dispatcher.aclose() for dispatcher in dispatchers))


def test_build_receivers_wires_every_enabled_listener(settings_factory: Any, audit: Any) -> None:
    settings = settings_factory(
        tcp_enabled=True,
        syslog_enabled=True,
        syslog_udp_enabled=True,
        rate_limit_events_per_minute=0,
    )

    receivers = build_receivers(settings, cast(Any, object()), audit, None)

    assert [receiver.name for receiver in receivers] == ["tcp_json", "syslog_tcp", "syslog_udp"]
    tcp, syslog_tcp, syslog_udp = (cast(Any, receiver) for receiver in receivers)
    assert tcp.port == settings.tcp_port
    assert syslog_tcp.port == syslog_udp.port == settings.syslog_port


def test_build_receivers_skips_disabled_listeners(settings_factory: Any, audit: Any) -> None:
    settings = settings_factory(tcp_enabled=False, syslog_enabled=False)

    assert build_receivers(settings, cast(Any, object()), audit, None) == []


def test_build_receivers_keeps_syslog_tcp_when_udp_is_disabled(
    settings_factory: Any, audit: Any
) -> None:
    settings = settings_factory(tcp_enabled=False, syslog_enabled=True, syslog_udp_enabled=False)

    assert [
        receiver.name for receiver in build_receivers(settings, cast(Any, object()), audit, None)
    ] == ["syslog_tcp"]
