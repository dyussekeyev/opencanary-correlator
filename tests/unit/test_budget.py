"""The alert budget: notifications are rationed, incidents never are."""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from pydantic import ValidationError

from opencanary_correlator.connectors.base import BaseDispatcher, DispatchResult, IncidentLike
from opencanary_correlator.connectors.dispatchers import (
    DiscordDispatcher,
    SlackDispatcher,
    SmtpDispatcher,
    TelegramDispatcher,
    WebhookDispatcher,
)
from opencanary_correlator.constants import KEY_INCIDENTS
from opencanary_correlator.core.budget import AlertBudget, BudgetSummary, render_budget_summary
from opencanary_correlator.core.engine import CorrelationEngine
from opencanary_correlator.core.incident import Incident, IncidentRepository
from opencanary_correlator.core.outbox import AlertOutbox
from opencanary_correlator.core.rules import build_rules
from opencanary_correlator.core.windows import DedupCache
from opencanary_correlator.schemas import CanaryEvent
from opencanary_correlator.storage.keys import budget_summary_key


class RecordingDispatcher(BaseDispatcher):
    """A person-facing channel: records alert bodies and notices."""

    name = "recording"

    def __init__(self) -> None:
        self.incidents: list[Incident] = []
        self.notices: list[str] = []

    async def dispatch(self, incident: IncidentLike) -> DispatchResult:
        assert isinstance(incident, Incident)
        self.incidents.append(incident)
        return DispatchResult(dispatcher=self.name, status="success")

    async def announce(self, message: str) -> DispatchResult:
        self.notices.append(message)
        return DispatchResult(dispatcher=self.name, status="success")


def make_budget(
    store: Any,
    settings: Any,
    audit: Any,
    clock: Any,
    dispatchers: list[BaseDispatcher] | None = None,
) -> AlertBudget:
    return AlertBudget(store, dispatchers or [RecordingDispatcher()], settings, audit, clock=clock)


def budget_settings(settings_factory: Any, **overrides: Any) -> Any:
    params: dict[str, Any] = {
        "alert_budget_enabled": True,
        "alert_budget_per_node": 2,
        "alert_budget_global": 10,
        "alert_budget_window": 3600,
    }
    params.update(overrides)
    return settings_factory(**params)


# --- Reservation ------------------------------------------------------------


async def test_a_node_notifies_up_to_its_limit_and_then_not_at_all(
    store: Any, settings_factory: Any, audit: Any, clock: Any
) -> None:
    budget = make_budget(store, budget_settings(settings_factory), audit, clock)

    assert [await budget.allow("canary-1") for _ in range(3)] == [True, True, False]


async def test_the_global_limit_bounds_every_canary_together(
    store: Any, settings_factory: Any, audit: Any, clock: Any
) -> None:
    settings = budget_settings(settings_factory, alert_budget_per_node=2, alert_budget_global=2)
    budget = make_budget(store, settings, audit, clock)

    assert await budget.allow("canary-1") is True
    assert await budget.allow("canary-2") is True
    # A brand-new canary has its whole per-node allowance, yet the window is spent.
    assert await budget.allow("canary-3") is False


async def test_a_new_window_starts_with_a_full_budget_even_across_replicas(
    store: Any, settings_factory: Any, audit: Any, clock: Any
) -> None:
    settings = budget_settings(settings_factory, alert_budget_per_node=1)
    replica_a = make_budget(store, settings, audit, clock)
    replica_b = make_budget(store, settings, audit, clock)

    assert await replica_a.allow("canary-1") is True
    # The second replica shares the counter, so scaling out does not double it.
    assert await replica_b.allow("canary-1") is False
    clock.advance(settings.alert_budget_window + 1)
    assert await replica_b.allow("canary-1") is True


async def test_a_refusal_is_counted_for_the_window_that_will_report_it(
    store: Any, settings_factory: Any, audit: Any, clock: Any
) -> None:
    settings = budget_settings(settings_factory, alert_budget_per_node=1)
    budget = make_budget(store, settings, audit, clock)
    start, end = budget.window_bounds()
    await budget.allow("canary-1")
    await budget.allow("canary-1")
    await budget.allow("canary-1")

    # Not due while the window is still open: the count is not final yet.
    assert await store.due_budget_summaries(now=end - 1, limit=10) == []
    assert await store.due_budget_summaries(now=end, limit=10) == [budget_summary_key(start)]
    assert await store.take_budget_summary(budget_summary_key(start)) == {"canary-1": 2}


# --- Summary ----------------------------------------------------------------


async def test_only_one_replica_delivers_a_summary(
    store: Any, settings_factory: Any, audit: Any, audit_stream: Any, clock: Any
) -> None:
    settings = budget_settings(settings_factory, alert_budget_per_node=1)
    first = RecordingDispatcher()
    second = RecordingDispatcher()
    budget_a = make_budget(store, settings, audit, clock, [first])
    budget_b = make_budget(store, settings, audit, clock, [second])
    await budget_a.allow("canary-1")
    await budget_a.allow("canary-1")
    clock.advance(settings.alert_budget_window)

    assert await budget_a.run_once() == 1
    assert await budget_b.run_once() == 0

    assert len(first.notices) == 1
    assert second.notices == []
    assert "Suppressed: 1 alerts" in first.notices[0]
    assert '"action":"alert_summary"' in audit_stream.getvalue()


async def test_a_summary_reports_every_withholding_instance(
    store: Any, settings_factory: Any, audit: Any, clock: Any
) -> None:
    settings = budget_settings(settings_factory, alert_budget_per_node=1, alert_budget_global=2)
    dispatcher = RecordingDispatcher()
    budget = make_budget(store, settings, audit, clock, [dispatcher])
    for _ in range(4):
        await budget.allow("canary-1")
    await budget.allow("canary-2")
    await budget.allow("canary-2")
    clock.advance(settings.alert_budget_window)

    await budget.run_once()

    notice = dispatcher.notices[0]
    assert "Suppressed: 4 alerts" in notice
    assert "Instances: 2" in notice
    assert "canary-1: 3" in notice
    assert "canary-2: 1" in notice


def test_the_rendered_summary_is_plain_text_and_flattened() -> None:
    summary = BudgetSummary(
        start=1_700_000_000,
        end=1_700_003_600,
        counts={"canary\n1": 3, "canary-2": 1},
    )

    text = render_budget_summary(summary)

    assert "Suppressed: 4 alerts" in text
    assert "Instances: 2" in text
    assert "canary 1: 3" in text  # a node id from the wire cannot break the layout
    assert text.splitlines()[0] == "🛡 OpenCanary: alert budget"


async def test_a_broken_summary_iteration_is_audited_and_the_loop_survives(
    store: Any, settings_factory: Any, audit: Any, audit_stream: Any, clock: Any
) -> None:
    import asyncio

    budget = make_budget(store, budget_settings(settings_factory), audit, clock)

    async def explode() -> int:
        raise RuntimeError("redis hiccup")

    await budget.start()
    budget.run_once = explode  # type: ignore[method-assign]
    await asyncio.sleep(0.05)
    await budget.stop()

    assert "alert_summary_failed" in audit_stream.getvalue()


# --- The engine's side ------------------------------------------------------


def make_engine(
    store: Any,
    settings: Any,
    audit: Any,
    clock: Any,
    dispatcher: BaseDispatcher,
    *,
    outbox: AlertOutbox | None,
    budget: Any,
) -> CorrelationEngine:
    channels = outbox.channels if outbox else ()
    repository = IncidentRepository(store, settings, audit, clock=clock, alert_channels=channels)
    return CorrelationEngine(
        rules=build_rules(store, repository, settings),
        dispatchers=[dispatcher],
        dedup=DedupCache(store, ttl=settings.dedup_ttl, lease=settings.dedup_lease),
        settings=settings,
        audit=audit,
        clock=clock,
        outbox=outbox,
        budget=budget,
    )


async def test_a_withheld_notification_leaves_the_incident_and_its_trail(
    store: Any, settings_factory: Any, audit: Any, audit_stream: Any, clock: Any, event_factory: Any
) -> None:
    settings = budget_settings(settings_factory, alert_budget_per_node=1)
    dispatcher = RecordingDispatcher()
    outbox = AlertOutbox(store, [dispatcher], settings, audit, clock=clock)
    budget = make_budget(store, settings, audit, clock)
    engine = make_engine(store, settings, audit, clock, dispatcher, outbox=outbox, budget=budget)
    # Spend the window before the event arrives: the next notification is over it.
    assert await budget.allow("canary-1") is True

    await engine.handle_event(CanaryEvent.model_validate(event_factory()))

    assert dispatcher.incidents == []
    incident_keys = await store.zrangebyscore(KEY_INCIDENTS, "-inf", "+inf")
    assert len(incident_keys) == 1
    # Stored and visible, and no pending delivery left to be retried later.
    assert await store.hgetall(incident_keys[0])
    assert await store.outbox_pending() == 0
    assert '"action":"alert_suppressed"' in audit_stream.getvalue()


async def test_a_budget_that_cannot_answer_does_not_silence_the_alert(
    store: Any, settings_factory: Any, audit: Any, audit_stream: Any, clock: Any, event_factory: Any
) -> None:
    settings = settings_factory()

    class BrokenBudget:
        async def allow(self, _node_id: str) -> bool:
            raise RuntimeError("redis hiccup")

    dispatcher = RecordingDispatcher()
    engine = make_engine(
        store, settings, audit, clock, dispatcher, outbox=None, budget=BrokenBudget()
    )

    await engine.handle_event(CanaryEvent.model_validate(event_factory()))

    assert len(dispatcher.incidents) == 1
    assert "alert_budget_failed" in audit_stream.getvalue()


async def test_the_budget_is_off_unless_it_is_switched_on(settings_factory: Any) -> None:
    assert settings_factory().alert_budget_enabled is False
    assert settings_factory(alert_budget_enabled=True).alert_budget_enabled is True


def test_a_per_node_limit_above_the_global_one_is_rejected(settings_factory: Any) -> None:
    with pytest.raises(ValidationError, match="alert_budget_per_node"):
        settings_factory(alert_budget_per_node=50, alert_budget_global=10)


# --- Notice payloads --------------------------------------------------------


def http_client() -> httpx.AsyncClient:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json={"ok": True})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client.calls = calls  # type: ignore[attr-defined]
    return client


async def test_a_webhook_refuses_a_notice_it_cannot_represent() -> None:
    dispatcher = WebhookDispatcher(url="https://siem.test/hook", client=http_client())

    result = await dispatcher.announce("OpenCanary: alert budget")

    assert result.status == "skipped"
    assert result.detail == "not_supported"


async def test_chat_and_mail_channels_carry_a_notice() -> None:
    message = "🛡 OpenCanary: alert budget\r\n\r\n🔕 Suppressed: 3 alerts"
    sent: list[Any] = []

    async def fake_send(item: Any, **kwargs: Any) -> Any:
        sent.append(item)
        return ({}, "ok")

    client = http_client()
    telegram = TelegramDispatcher(token="123:abc", chat_id="-100", client=client)
    slack = SlackDispatcher(url="https://hooks.slack.test/x", client=client)
    discord = DiscordDispatcher(url="https://discord.test/hook", client=client)
    smtp = SmtpDispatcher(
        host="smtp.test",
        port=25,
        sender="alerts@example.test",
        recipients=["soc@example.test"],
        send=fake_send,
    )
    try:
        results = [await channel.announce(message) for channel in (telegram, slack, discord, smtp)]
    finally:
        for channel in (telegram, slack, discord, smtp):
            await channel.aclose()

    assert [result.status for result in results] == ["success"] * 4
    bodies = [request.content for request in client.calls]  # type: ignore[attr-defined]
    assert b'"text"' in bodies[0] and b"Suppressed" in bodies[0]
    # A notice is plain text: Telegram must not be asked to parse it as markdown.
    assert b"parse_mode" not in bodies[0]
    assert b'"text"' in bodies[1] and b"Suppressed" in bodies[1]
    assert b'"content"' in bodies[2] and b"Suppressed" in bodies[2]
    # The mail takes its subject from the headline and keeps the body intact.
    assert sent[0]["Subject"] == "🛡 OpenCanary: alert budget"
    assert "Suppressed: 3 alerts" in sent[0].get_content()
