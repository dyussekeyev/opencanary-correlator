"""Service messages: the correlator reporting its own degradation, once."""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from pydantic import ValidationError

from opencanary_correlator.app.channels import CHANNEL_SPECS
from opencanary_correlator.app.parser import CorrelatorStartupError
from opencanary_correlator.app.runner import (
    _require_configured_service_channels as require_configured_service_channels,
)
from opencanary_correlator.config_validation import KNOWN_CHANNEL_NAMES
from opencanary_correlator.connectors.base import BaseDispatcher, DispatchResult, IncidentLike
from opencanary_correlator.connectors.dispatchers import (
    DiscordDispatcher,
    SlackDispatcher,
    SmtpDispatcher,
    TelegramDispatcher,
    WebhookDispatcher,
)
from opencanary_correlator.connectors.dispatchers.alert_text import render_service_message
from opencanary_correlator.core.engine import ALL_CHANNELS_FAILING_THRESHOLD, CorrelationEngine
from opencanary_correlator.core.incident import IncidentRepository
from opencanary_correlator.core.outbox import AlertOutbox
from opencanary_correlator.core.rules import build_rules
from opencanary_correlator.core.service_messages import (
    ServiceKind,
    ServiceMessage,
    ServiceNotifier,
    Severity,
)
from opencanary_correlator.core.windows import DedupCache
from opencanary_correlator.enrichment.service import IncidentEnricher
from opencanary_correlator.schemas import CanaryEvent
from opencanary_correlator.storage import keys

TELEGRAM_TOKEN = "123456:AAH-service-secret"
WEBHOOK_URL = "https://hooks.test/services/SECRET-PATH"


class RecordingDispatcher(BaseDispatcher):
    """A channel that accepts service messages and keeps them."""

    name = "recording"

    def __init__(self, *, name: str = "recording", status: str = "success") -> None:
        self.name = name  # type: ignore[misc]
        self.messages: list[ServiceMessage] = []
        self._status = status

    async def dispatch(self, incident: IncidentLike) -> DispatchResult:
        return DispatchResult(dispatcher=self.name, status="success")

    async def notify(self, message: ServiceMessage) -> DispatchResult:
        self.messages.append(message)
        return DispatchResult(dispatcher=self.name, status=self._status)  # type: ignore[arg-type]


class SilentDispatcher(BaseDispatcher):
    """A channel that never learned to carry a service message."""

    name = "silent"

    async def dispatch(self, incident: IncidentLike) -> DispatchResult:
        return DispatchResult(dispatcher=self.name, status="success")


def service_settings(settings_factory: Any, **overrides: Any) -> Any:
    params: dict[str, Any] = {
        "service_enabled": True,
        "service_categories": ["enrichment", "channels", "lifecycle"],
        "service_cooldown": 3600,
        "service_min_severity": "warning",
    }
    params.update(overrides)
    return settings_factory(**params)


def make_notifier(
    store: Any, settings: Any, audit: Any, dispatchers: list[BaseDispatcher]
) -> ServiceNotifier:
    return ServiceNotifier(store, dispatchers, settings, audit)


# --- Switches ---------------------------------------------------------------


async def test_nothing_is_sent_while_the_feature_is_off(
    store: Any, settings_factory: Any, audit: Any
) -> None:
    dispatcher = RecordingDispatcher()
    notifier = make_notifier(store, settings_factory(), audit, [dispatcher])

    assert notifier.enabled is False
    assert await notifier.notify(ServiceKind.GEO_UNAVAILABLE, title="GeoIP failed") is False
    assert dispatcher.messages == []
    # Not even the suppression slot: a disabled notifier touches nothing.
    mute, _repeat = keys.service_message_keys(ServiceKind.GEO_UNAVAILABLE.value, "geoip")
    assert not await store.exists(mute)


async def test_a_category_that_is_switched_off_stays_silent(
    store: Any, settings_factory: Any, audit: Any
) -> None:
    dispatcher = RecordingDispatcher()
    settings = service_settings(settings_factory, service_categories=["enrichment"])
    notifier = make_notifier(store, settings, audit, [dispatcher])

    assert await notifier.notify(ServiceKind.LIFECYCLE_STARTED, title="correlator started") is False
    assert dispatcher.messages == []


async def test_a_message_quieter_than_the_floor_is_dropped(
    store: Any, settings_factory: Any, audit: Any
) -> None:
    dispatcher = RecordingDispatcher()
    settings = service_settings(settings_factory, service_min_severity="critical")
    notifier = make_notifier(store, settings, audit, [dispatcher])

    assert await notifier.notify(ServiceKind.GEO_UNAVAILABLE, title="GeoIP failed") is False
    assert await notifier.notify(ServiceKind.VIRUSTOTAL_KEY_REJECTED, title="Key rejected") is True
    assert [message.kind for message in dispatcher.messages] == [
        ServiceKind.VIRUSTOTAL_KEY_REJECTED
    ]


# --- Storm proof ------------------------------------------------------------


async def test_a_storm_produces_one_message_and_a_count(
    store: Any, settings_factory: Any, audit: Any, audit_stream: Any
) -> None:
    dispatcher = RecordingDispatcher()
    notifier = make_notifier(store, service_settings(settings_factory), audit, [dispatcher])

    for _ in range(100):
        await notifier.notify(
            ServiceKind.VIRUSTOTAL_UNAVAILABLE, title="VirusTotal is unreachable", subject="vt"
        )

    assert len(dispatcher.messages) == 1
    assert '"action":"service_message_suppressed"' in audit_stream.getvalue()
    assert audit_stream.getvalue().count('"action":"service_message_suppressed"') == 99

    # The cooldown ends: the next one reports how often it happened meanwhile.
    mute, _repeat = keys.service_message_keys(ServiceKind.VIRUSTOTAL_UNAVAILABLE.value, "vt")
    await store.delete(mute)
    await notifier.notify(
        ServiceKind.VIRUSTOTAL_UNAVAILABLE, title="VirusTotal is unreachable", subject="vt"
    )

    assert len(dispatcher.messages) == 2
    assert dispatcher.messages[-1].count == 100
    assert "Repeated 100 times" in render_service_message(dispatcher.messages[-1])


async def test_two_subjects_do_not_silence_each_other(
    store: Any, settings_factory: Any, audit: Any
) -> None:
    dispatcher = RecordingDispatcher()
    notifier = make_notifier(store, service_settings(settings_factory), audit, [dispatcher])

    await notifier.notify(ServiceKind.CHANNEL_CIRCUIT_OPEN, title="slack paused", subject="slack")
    await notifier.notify(ServiceKind.CHANNEL_CIRCUIT_OPEN, title="smtp paused", subject="smtp")

    assert len(dispatcher.messages) == 2


# --- Routing and audit ------------------------------------------------------


async def test_routing_sends_only_to_the_named_channels(
    store: Any, settings_factory: Any, audit: Any
) -> None:
    slack = RecordingDispatcher(name="slack")
    smtp = RecordingDispatcher(name="smtp")
    settings = service_settings(settings_factory, service_channels=["telegram"])
    notifier = make_notifier(store, settings, audit, [slack, smtp])

    # No telegram dispatcher was built, so nothing is left to send through.
    assert notifier.channels == ()
    assert await notifier.notify(ServiceKind.GEO_UNAVAILABLE, title="GeoIP failed") is False


async def test_an_empty_routing_list_means_every_channel(
    store: Any, settings_factory: Any, audit: Any
) -> None:
    slack = RecordingDispatcher(name="slack")
    smtp = RecordingDispatcher(name="smtp")
    notifier = make_notifier(store, service_settings(settings_factory), audit, [slack, smtp])

    assert await notifier.notify(ServiceKind.GEO_UNAVAILABLE, title="GeoIP failed") is True
    assert len(slack.messages) == 1
    assert len(smtp.messages) == 1


async def test_a_channel_that_cannot_carry_a_message_is_reported_not_fatal(
    store: Any, settings_factory: Any, audit: Any, audit_stream: Any
) -> None:
    silent = SilentDispatcher()
    recording = RecordingDispatcher()
    notifier = make_notifier(store, service_settings(settings_factory), audit, [silent, recording])

    assert await notifier.notify(ServiceKind.GEO_UNAVAILABLE, title="GeoIP failed") is True
    assert '"reason":"not_supported"' in audit_stream.getvalue()
    assert len(recording.messages) == 1


async def test_every_delivery_is_audited(
    store: Any, settings_factory: Any, audit: Any, audit_stream: Any
) -> None:
    settings = service_settings(settings_factory, service_min_severity="info")
    notifier = make_notifier(store, settings, audit, [RecordingDispatcher()])

    await notifier.notify(ServiceKind.LIFECYCLE_STARTED, title="correlator started")

    assert '"action":"service_message_sent"' in audit_stream.getvalue()
    assert '"kind":"lifecycle.started"' in audit_stream.getvalue()


# --- Rendering --------------------------------------------------------------


def message(kind: ServiceKind, **overrides: Any) -> ServiceMessage:
    params: dict[str, Any] = {
        "kind": kind,
        "title": "service message",
        "lines": ("The API answered 401 or 403",),
    }
    params.update(overrides)
    return ServiceMessage(**params)


def test_plain_text_uses_crlf_between_rows() -> None:
    text = render_service_message(message(ServiceKind.VIRUSTOTAL_KEY_REJECTED))

    assert text.splitlines() == [
        "🛑 OpenCanary service: service message",
        "",
        "• The API answered 401 or 403",
    ]
    assert "\r\n" in text


def test_telegram_escapes_markup_and_discord_bolds() -> None:
    telegram = render_service_message(
        message(ServiceKind.VIRUSTOTAL_KEY_REJECTED, title="API v2.0 (legacy)"), flavor="telegram"
    )
    discord = render_service_message(message(ServiceKind.VIRUSTOTAL_KEY_REJECTED), flavor="discord")

    # MarkdownV2 treats '.' and parentheses as control characters: unescaped they
    # make Telegram reject the whole message.
    assert r"API v2\.0 \(legacy\)" in telegram
    assert "**service message**" in discord


def test_a_repeat_count_is_shown_only_when_there_is_one() -> None:
    single = render_service_message(message(ServiceKind.VIRUSTOTAL_KEY_REJECTED))
    repeated = render_service_message(message(ServiceKind.VIRUSTOTAL_KEY_REJECTED, count=4))

    assert "Repeated" not in single
    assert "Repeated 4 times" in repeated


def test_the_severity_decides_the_symbol() -> None:
    assert message(ServiceKind.VIRUSTOTAL_KEY_REJECTED).severity is Severity.CRITICAL
    assert render_service_message(message(ServiceKind.VIRUSTOTAL_KEY_REJECTED)).startswith("🛑")
    assert render_service_message(message(ServiceKind.GEO_UNAVAILABLE)).startswith("⚠️")
    assert render_service_message(message(ServiceKind.LIFECYCLE_STARTED)).startswith("ℹ️")


def test_a_long_line_is_clipped_for_the_channel() -> None:
    text = render_service_message(
        message(ServiceKind.GEO_UNAVAILABLE, lines=("x" * 5000,)), max_length=200
    )

    assert len(text) <= 200
    assert text.endswith("…")


# --- Channel payloads -------------------------------------------------------


def http_client() -> Any:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json={"ok": True})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client.calls = calls  # type: ignore[attr-defined]
    return client


async def test_telegram_sends_markdown_service_messages() -> None:
    client = http_client()
    dispatcher = TelegramDispatcher(token=TELEGRAM_TOKEN, chat_id="-100", client=client)
    try:
        result = await dispatcher.notify(
            message(ServiceKind.VIRUSTOTAL_KEY_REJECTED, title="Key rejected")
        )
    finally:
        await dispatcher.aclose()

    import json

    body = json.loads(client.calls[0].content)  # type: ignore[attr-defined]
    assert result.status == "success"
    assert body["chat_id"] == "-100"
    assert body["parse_mode"] == "MarkdownV2"
    assert "Key rejected" in body["text"]


async def test_slack_discord_and_webhook_carry_a_service_message() -> None:
    import json

    client = http_client()
    slack = SlackDispatcher(url="https://hooks.slack.test/x", client=client)
    discord = DiscordDispatcher(url="https://discord.test/hook", client=client)
    webhook = WebhookDispatcher(url="https://siem.test/hook", client=client)
    try:
        geo = message(ServiceKind.GEO_UNAVAILABLE, title="GeoIP lookup failed")
        await slack.notify(geo)
        await discord.notify(geo)
        await webhook.notify(geo)
    finally:
        for dispatcher in (slack, discord, webhook):
            await dispatcher.aclose()

    slack_body, discord_body, webhook_body = (
        json.loads(request.content)
        for request in client.calls  # type: ignore[attr-defined]
    )
    assert "GeoIP" in slack_body["text"]
    assert "GeoIP" in discord_body["content"]
    # A SIEM rule keyed on an incident must not match a degradation report.
    assert set(webhook_body) == {"kind", "severity", "title", "text", "count"}
    assert webhook_body["kind"] == "enrichment.geo.unavailable"
    assert webhook_body["severity"] == "warning"


async def test_smtp_puts_the_severity_in_the_subject() -> None:
    sent: list[Any] = []

    async def fake_send(item: Any, **kwargs: Any) -> Any:
        sent.append(item)
        return ({}, "ok")

    dispatcher = SmtpDispatcher(
        host="smtp.test",
        port=25,
        sender="alerts@example.test",
        recipients=["soc@example.test"],
        send=fake_send,
    )

    result = await dispatcher.notify(
        message(ServiceKind.VIRUSTOTAL_KEY_REJECTED, title="Key rejected")
    )

    assert result.status == "success"
    assert sent[0]["Subject"] == "[critical] Key rejected"
    assert "The API answered 401 or 403" in sent[0].get_content()


async def test_the_default_contract_refuses_instead_of_swallowing() -> None:
    with pytest.raises(NotImplementedError):
        await SilentDispatcher().notify(message(ServiceKind.GEO_UNAVAILABLE))


# --- Sources: enrichment ----------------------------------------------------


class FakeVirusTotal:
    """A VirusTotal client stub with one scripted outcome."""

    name = "virustotal"

    def __init__(self, status: str, window: str | None = None) -> None:
        self._status = status
        self._window = window
        self.calls = 0

    async def report(self, _ip: str) -> tuple[Any, str]:
        self.calls += 1
        return None, self._status

    async def exhausted_window(self) -> str | None:
        return self._window

    async def aclose(self) -> None:
        return None


def enricher_with(
    store: Any, settings: Any, audit: Any, dispatcher: RecordingDispatcher, vt: Any
) -> IncidentEnricher:
    notifier = make_notifier(store, settings, audit, [dispatcher])
    return IncidentEnricher(virustotal=vt, audit=audit, notifier=notifier)


async def test_a_rejected_key_is_reported_once(
    store: Any, settings_factory: Any, audit: Any, audit_stream: Any
) -> None:
    dispatcher = RecordingDispatcher()
    vt = FakeVirusTotal("unauthorized")
    settings = service_settings(settings_factory, virustotal_api_key=TELEGRAM_TOKEN)
    enricher = enricher_with(store, settings, audit, dispatcher, vt)

    for _ in range(5):
        await enricher.enrich("74.22.3.1")

    assert [message.kind for message in dispatcher.messages] == [
        ServiceKind.VIRUSTOTAL_KEY_REJECTED
    ]
    assert '"reason":"key_rejected"' in audit_stream.getvalue()
    # The alert itself says nothing about the key: it shows "unavailable".
    assert vt.calls == 5


async def test_a_spent_quota_names_the_window(
    store: Any, settings_factory: Any, audit: Any
) -> None:
    dispatcher = RecordingDispatcher()
    enricher = enricher_with(
        store, service_settings(settings_factory), audit, dispatcher, FakeVirusTotal("quota", "day")
    )

    await enricher.enrich("74.22.3.2")

    assert dispatcher.messages[0].kind is ServiceKind.VIRUSTOTAL_QUOTA
    assert any("day" in line for line in dispatcher.messages[0].lines)


async def test_an_unreachable_provider_is_reported(
    store: Any, settings_factory: Any, audit: Any
) -> None:
    dispatcher = RecordingDispatcher()
    enricher = enricher_with(
        store,
        service_settings(settings_factory),
        audit,
        dispatcher,
        FakeVirusTotal("unavailable"),
    )

    await enricher.enrich("74.22.3.3")

    assert dispatcher.messages[0].kind is ServiceKind.VIRUSTOTAL_UNAVAILABLE
    assert any("unavailable" in line for line in dispatcher.messages[0].lines)


class BrokenGeo:
    """A GeoIP reader that fails on every lookup, like a corrupted MMDB."""

    def lookup(self, _ip: str) -> Any:
        raise RuntimeError("corrupt database")

    def close(self) -> None:
        return None


async def test_a_broken_geo_database_is_reported(
    store: Any, settings_factory: Any, audit: Any
) -> None:
    dispatcher = RecordingDispatcher()
    notifier = make_notifier(store, service_settings(settings_factory), audit, [dispatcher])
    enricher = IncidentEnricher(geo=BrokenGeo(), audit=audit, notifier=notifier)  # type: ignore[arg-type]

    assert await enricher.enrich("74.22.3.4") is None

    assert dispatcher.messages[0].kind is ServiceKind.GEO_UNAVAILABLE
    assert "RuntimeError" in dispatcher.messages[0].lines[0]


async def test_no_secret_reaches_a_service_message(
    store: Any, settings_factory: Any, audit: Any
) -> None:
    dispatcher = RecordingDispatcher()
    settings = service_settings(
        settings_factory, virustotal_api_key=TELEGRAM_TOKEN, webhook_urls=[WEBHOOK_URL]
    )
    enricher = enricher_with(store, settings, audit, dispatcher, FakeVirusTotal("unauthorized"))

    await enricher.enrich("74.22.3.5")

    text = render_service_message(dispatcher.messages[0])
    assert TELEGRAM_TOKEN not in text
    assert "SECRET-PATH" not in text
    assert "virustotal.com" not in text


# --- Configuration ----------------------------------------------------------


def test_an_unknown_service_channel_is_rejected(settings_factory: Any) -> None:
    with pytest.raises(ValidationError, match="service_channels"):
        settings_factory(service_channels=["telegrm"])


def test_an_unknown_service_category_is_rejected(settings_factory: Any) -> None:
    with pytest.raises(ValidationError, match="service_categories"):
        settings_factory(service_categories=["enrichment", "digest"])


def test_severity_aliases_are_normalised_and_nonsense_is_rejected(
    settings_factory: Any,
) -> None:
    assert settings_factory(service_min_severity="WARN").service_min_severity == "warning"
    assert settings_factory(service_min_severity="CRITICAL").service_min_severity == "critical"
    with pytest.raises(ValidationError):
        settings_factory(service_min_severity="loud")


def test_the_csv_lists_are_split(settings_factory: Any) -> None:
    settings = settings_factory(
        service_channels="telegram, slack", service_categories="channels,lifecycle"
    )

    assert settings.service_channels == ["telegram", "slack"]
    assert settings.service_categories == ["channels", "lifecycle"]


def test_the_known_channel_names_match_the_built_channels() -> None:
    assert set(KNOWN_CHANNEL_NAMES) == {spec.name for spec in CHANNEL_SPECS}


def test_a_configured_channel_that_was_never_built_stops_startup(
    settings_factory: Any,
) -> None:
    settings = settings_factory(service_enabled=True, service_channels=["telegram"])

    with pytest.raises(CorrelatorStartupError, match="telegram"):
        require_configured_service_channels(settings, [RecordingDispatcher(name="smtp")])


def test_a_disabled_notifier_does_not_check_its_channels(settings_factory: Any) -> None:
    settings = settings_factory(service_enabled=False, service_channels=["telegram"])

    # Nothing is sent, so a name that matches no dispatcher is not an error.
    require_configured_service_channels(settings, [])


# --- Sources: channels ------------------------------------------------------


class BreakerOpenDispatcher(BaseDispatcher):
    """A channel whose breaker is open, so no attempt is made."""

    name = "telegram"

    def __init__(self) -> None:
        self.attempts = 0

    async def dispatch(self, incident: IncidentLike) -> DispatchResult:
        self.attempts += 1
        return DispatchResult(dispatcher=self.name, status="skipped", detail="circuit_open")


class FailingDispatcher(BaseDispatcher):
    name = "smtp"

    async def dispatch(self, incident: IncidentLike) -> DispatchResult:
        return DispatchResult(dispatcher=self.name, status="error", detail="http_503")


def make_engine(
    store: Any,
    settings: Any,
    audit: Any,
    clock: Any,
    dispatchers: list[BaseDispatcher],
    notifier: ServiceNotifier,
) -> CorrelationEngine:
    repository = IncidentRepository(store, settings, audit, clock=clock)
    outbox = AlertOutbox(store, dispatchers, settings, audit)
    return CorrelationEngine(
        rules=build_rules(store, repository, settings),
        dispatchers=dispatchers,
        dedup=DedupCache(store, ttl=settings.dedup_ttl, lease=settings.dedup_lease),
        settings=settings,
        audit=audit,
        clock=clock,
        outbox=outbox,
        notifier=notifier,
    )


async def test_an_open_breaker_is_reported(
    store: Any, settings_factory: Any, audit: Any, clock: Any, event_factory: Any
) -> None:
    breaker = BreakerOpenDispatcher()
    recorder = RecordingDispatcher()
    settings = service_settings(settings_factory)
    notifier = make_notifier(store, settings, audit, [recorder])
    engine = make_engine(store, settings, audit, clock, [breaker], notifier)

    await engine.handle_event(CanaryEvent.model_validate(event_factory()))

    assert [message.kind for message in recorder.messages] == [ServiceKind.CHANNEL_CIRCUIT_OPEN]
    assert "telegram" in recorder.messages[0].title


async def test_no_channel_delivering_is_reported_after_a_few_alerts(
    store: Any, settings_factory: Any, audit: Any, clock: Any, event_factory: Any
) -> None:
    recorder = RecordingDispatcher()
    settings = service_settings(settings_factory)
    notifier = make_notifier(store, settings, audit, [recorder])
    engine = make_engine(store, settings, audit, clock, [FailingDispatcher()], notifier)

    for index in range(ALL_CHANNELS_FAILING_THRESHOLD):
        await engine.handle_event(
            CanaryEvent.model_validate(event_factory(src_host=f"10.2.0.{index}"))
        )

    assert [message.kind for message in recorder.messages] == [ServiceKind.CHANNEL_ALL_FAILING]
    assert f"{ALL_CHANNELS_FAILING_THRESHOLD} consecutive alerts" in recorder.messages[0].lines[0]


async def test_a_delivered_alert_resets_the_counter(
    store: Any, settings_factory: Any, audit: Any, clock: Any, event_factory: Any
) -> None:
    recorder = RecordingDispatcher()
    settings = service_settings(settings_factory)
    notifier = make_notifier(store, settings, audit, [recorder])
    failing = FailingDispatcher()
    engine = make_engine(store, settings, audit, clock, [failing], notifier)

    await engine.handle_event(CanaryEvent.model_validate(event_factory(src_host="10.3.0.1")))
    await engine.handle_event(CanaryEvent.model_validate(event_factory(src_host="10.3.0.2")))
    # The channel recovers, so the run of failures is broken.
    failing.dispatch = RecordingDispatcher().dispatch  # type: ignore[method-assign]
    await engine.handle_event(CanaryEvent.model_validate(event_factory(src_host="10.3.0.3")))
    failing.dispatch = FailingDispatcher().dispatch  # type: ignore[method-assign]
    await engine.handle_event(CanaryEvent.model_validate(event_factory(src_host="10.3.0.4")))

    assert [message.kind for message in recorder.messages] == []
