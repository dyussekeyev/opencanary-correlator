"""The alert outbox: a decided notification either arrives or is visible."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from opencanary_correlator.connectors.base import BaseDispatcher, DispatchResult, IncidentLike
from opencanary_correlator.constants import KEY_INCIDENTS
from opencanary_correlator.core.engine import CorrelationEngine
from opencanary_correlator.core.incident import Incident, IncidentRepository
from opencanary_correlator.core.outbox import BACKOFF_SECONDS, AlertOutbox
from opencanary_correlator.core.rules import build_rules
from opencanary_correlator.core.windows import DedupCache
from opencanary_correlator.schemas import CanaryEvent
from opencanary_correlator.storage.keys import delivered_key, outbox_alert_key


class RecordingDispatcher(BaseDispatcher):
    name = "recording"

    def __init__(self) -> None:
        self.incidents: list[Incident] = []

    async def dispatch(self, incident: IncidentLike) -> DispatchResult:
        assert isinstance(incident, Incident)
        self.incidents.append(incident)
        return DispatchResult(dispatcher=self.name, status="success")


class FailingDispatcher(BaseDispatcher):
    name = "recording"

    def __init__(self) -> None:
        self.calls = 0

    async def dispatch(self, incident: IncidentLike) -> DispatchResult:
        self.calls += 1
        return DispatchResult(dispatcher=self.name, status="error", detail="503")


class RaisingDispatcher(BaseDispatcher):
    name = "recording"

    async def dispatch(self, incident: IncidentLike) -> DispatchResult:
        raise RuntimeError("channel down")


def make_repository(store: Any, settings: Any, audit: Any, clock: Any, channels: tuple[str, ...]):
    return IncidentRepository(store, settings, audit, clock=clock, alert_channels=channels)


def make_engine(
    store: Any,
    settings: Any,
    audit: Any,
    clock: Any,
    dispatcher: BaseDispatcher,
    *,
    outbox: AlertOutbox | None,
    enricher: Any | None = None,
) -> CorrelationEngine:
    repository = make_repository(store, settings, audit, clock, outbox.channels if outbox else ())
    return CorrelationEngine(
        rules=build_rules(store, repository, settings),
        dispatchers=[dispatcher],
        dedup=DedupCache(store, ttl=settings.dedup_ttl, lease=settings.dedup_lease),
        settings=settings,
        audit=audit,
        clock=clock,
        outbox=outbox,
        enricher=enricher,
    )


async def test_a_new_incident_enqueues_one_delivery_per_channel(
    store: Any, settings_factory: Any, audit: Any, clock: Any, event_factory: Any
) -> None:
    repository = make_repository(store, settings_factory(), audit, clock, ("telegram", "smtp"))
    event = CanaryEvent.model_validate(event_factory())

    incident = await repository.record("ftp.login_attempt", event)

    assert incident is not None
    assert await store.outbox_pending() == 0  # undecided targets are never runnable
    assert len(await store.due_alerts(now=clock(), limit=10, preparing=True)) == 1
    entry = await store.read_alert(f"{incident.key}#telegram")
    assert entry is not None
    assert entry["channel"] == "telegram"
    assert entry["incident"] == incident.key
    assert entry["attempts"] == "0"


async def test_a_merge_enqueues_nothing(
    store: Any, settings_factory: Any, audit: Any, clock: Any, event_factory: Any
) -> None:
    repository = make_repository(store, settings_factory(), audit, clock, ("telegram",))
    first = CanaryEvent.model_validate(event_factory(src_port=40000))
    second = CanaryEvent.model_validate(event_factory(src_port=40001))

    assert await repository.record("ftp.login_attempt", first) is not None
    assert await repository.record("ftp.login_attempt", second) is None

    # The merge notified nobody, so it owed nobody: one incident, one delivery.
    assert await store.outbox_pending() == 0
    assert len(await store.due_alerts(now=clock(), limit=10, preparing=True)) == 1


async def test_a_successful_inline_delivery_settles_the_entry(
    store: Any, settings_factory: Any, audit: Any, clock: Any, event_factory: Any
) -> None:
    settings = settings_factory()
    dispatcher = RecordingDispatcher()
    outbox = AlertOutbox(store, [dispatcher], settings, audit, clock=clock)
    engine = make_engine(store, settings, audit, clock, dispatcher, outbox=outbox)

    await engine.handle_event(CanaryEvent.model_validate(event_factory()))

    assert len(dispatcher.incidents) == 1
    assert await store.outbox_pending() == 0
    assert await store.exists(delivered_key(f"{dispatcher.incidents[0].key}#recording"))


async def test_a_failed_inline_delivery_is_rescheduled_with_a_backoff(
    store: Any, settings_factory: Any, audit: Any, clock: Any, event_factory: Any
) -> None:
    settings = settings_factory()
    dispatcher = FailingDispatcher()
    outbox = AlertOutbox(store, [dispatcher], settings, audit, clock=clock)
    engine = make_engine(store, settings, audit, clock, dispatcher, outbox=outbox)

    await engine.handle_event(CanaryEvent.model_validate(event_factory()))
    incident_key = (await store.zrangebyscore(KEY_INCIDENTS, "-inf", "+inf"))[0]
    entry = await store.read_alert(f"{incident_key}#recording")

    assert entry is not None
    assert entry["attempts"] == "1"
    assert entry["last_error"] == "503"  # safe structured code is preserved
    # Scheduled, not due: the first retry waits out the first backoff.
    assert await store.due_alerts(now=clock(), limit=10) == []
    clock.advance(BACKOFF_SECONDS[0] + 0.1)
    assert await store.due_alerts(now=clock(), limit=10) == [f"{incident_key}#recording"]


async def test_the_worker_delivers_what_the_process_dropped(
    store: Any, settings_factory: Any, audit: Any, clock: Any, event_factory: Any
) -> None:
    """A crash between the incident write and the dispatch loses nothing."""
    settings = settings_factory()
    dispatcher = RaisingDispatcher()
    outbox = AlertOutbox(store, [dispatcher], settings, audit, clock=clock)
    engine = make_engine(store, settings, audit, clock, dispatcher, outbox=outbox)
    await engine.handle_event(CanaryEvent.model_validate(event_factory()))
    assert await store.outbox_pending() == 1

    recovered = RecordingDispatcher()
    worker = AlertOutbox(store, [recovered], settings, audit, clock=clock)
    clock.advance(BACKOFF_SECONDS[0] + 0.1)

    assert await worker.run_once() == 1
    assert len(recovered.incidents) == 1
    assert await store.outbox_pending() == 0


async def test_a_delivery_is_buried_after_its_last_attempt(
    store: Any, settings_factory: Any, audit: Any, audit_stream: Any, clock: Any, event_factory: Any
) -> None:
    settings = settings_factory(outbox_max_attempts=1)
    dispatcher = FailingDispatcher()
    outbox = AlertOutbox(store, [dispatcher], settings, audit, clock=clock)
    engine = make_engine(store, settings, audit, clock, dispatcher, outbox=outbox)
    await engine.handle_event(CanaryEvent.model_validate(event_factory()))

    clock.advance(BACKOFF_SECONDS[0] + 0.1)
    assert await outbox.run_once() == 0

    assert dispatcher.calls == 1  # max_attempts includes the first, inline attempt
    assert await store.outbox_pending() == 0
    assert await store.outbox_dead() == 1
    assert "alert_dead_letter" in audit_stream.getvalue()


async def test_an_unknown_channel_is_buried_instead_of_retried(
    store: Any, settings_factory: Any, audit: Any, audit_stream: Any, clock: Any, event_factory: Any
) -> None:
    settings = settings_factory()
    repository = make_repository(store, settings, audit, clock, ("telegram",))
    event = CanaryEvent.model_validate(event_factory())
    incident = await repository.record("ftp.login_attempt", event)
    assert incident is not None

    # The worker has no Telegram dispatcher: it cannot ever deliver this.
    worker = AlertOutbox(store, [RecordingDispatcher()], settings, audit, clock=clock)

    assert await worker.run_once() == 0
    assert await store.outbox_dead() == 1
    assert "unknown_target" in audit_stream.getvalue()


async def test_a_delivery_whose_incident_is_gone_is_buried(
    store: Any, settings_factory: Any, audit: Any, audit_stream: Any, clock: Any
) -> None:
    """The entry names an incident an operator (or a TTL) removed."""
    settings = settings_factory()
    entry_id = "incident:ftplogin:10.0.0.9:1#recording"
    await store.enqueue_alert(
        entry_id, incident_key="incident:ftplogin:10.0.0.9:1", channel="recording", score=clock()
    )
    worker = AlertOutbox(store, [RecordingDispatcher()], settings, audit, clock=clock)

    assert await worker.run_once() == 0
    assert await store.outbox_dead() == 1
    assert "incident_gone" in audit_stream.getvalue()


async def test_a_timing_out_channel_is_retried_not_buried(
    store: Any, settings_factory: Any, audit: Any, audit_stream: Any, clock: Any, event_factory: Any
) -> None:
    settings = settings_factory(dispatch_timeout=0.01)

    class SlowDispatcher(BaseDispatcher):
        name = "recording"

        async def dispatch(self, incident: IncidentLike) -> DispatchResult:
            await asyncio.sleep(0.2)
            return DispatchResult(dispatcher=self.name, status="success")

    repository = make_repository(store, settings, audit, clock, ("recording",))
    await repository.record("ftp.login_attempt", CanaryEvent.model_validate(event_factory()))
    worker = AlertOutbox(store, [SlowDispatcher()], settings, audit, clock=clock)

    assert await worker.run_once() == 0

    assert await store.outbox_pending() == 1
    assert await store.outbox_dead() == 0
    assert '"reason":"timeout"' in audit_stream.getvalue()


async def test_two_replicas_never_claim_the_same_delivery(
    store: Any, settings_factory: Any, audit: Any, clock: Any, event_factory: Any
) -> None:
    settings = settings_factory()
    repository = make_repository(store, settings, audit, clock, ("telegram",))
    incident = await repository.record(
        "ftp.login_attempt", CanaryEvent.model_validate(event_factory())
    )
    worker = AlertOutbox(store, [], settings, audit, clock=clock)
    assert await worker.prepare(incident)
    entry_id = f"{incident.key}#telegram"
    first = await store.claim_alert(entry_id, now=clock(), lease=60, max_attempts=8)
    second = await store.claim_alert(entry_id, now=clock(), lease=60, max_attempts=8)
    assert len(first) == 32
    assert second == ""
    # Recovery gets a NEW owner, not the stale owner's token.
    recovered = await store.claim_alert(entry_id, now=clock() + 61, lease=60, max_attempts=8)
    assert len(recovered) == 32
    assert recovered != first
    for state in ("delivered", "ready", "dead"):
        assert not await store.transition_alert(
            entry_id,
            owner=first,
            now=clock() + 61,
            state=state,
        )
    assert (await store.read_alert(entry_id))["owner"] == recovered


async def test_settling_an_entry_that_never_existed_is_harmless(
    store: Any, settings_factory: Any, audit: Any, clock: Any
) -> None:
    assert not await store.transition_alert(
        "incident:ftplogin:10.0.0.5:1#recording", owner="stale", now=clock(), state="delivered"
    )

    assert not await store.exists(outbox_alert_key("incident:ftplogin:10.0.0.5:1#recording"))


async def test_a_broken_worker_iteration_is_audited_and_the_loop_survives(
    store: Any, settings_factory: Any, audit: Any, audit_stream: Any, clock: Any
) -> None:
    settings = settings_factory()
    outbox = AlertOutbox(store, [RecordingDispatcher()], settings, audit, clock=clock)

    async def explode() -> int:
        raise RuntimeError("redis hiccup")

    await outbox.start()
    outbox.run_once = explode  # type: ignore[method-assign]

    await asyncio.sleep(0.05)
    await outbox.stop()

    assert "outbox_failed" in audit_stream.getvalue()


async def test_two_targets_of_one_channel_keep_independent_debts(
    store: Any, settings_factory: Any, audit: Any, clock: Any, event_factory: Any
) -> None:
    first, second = RecordingDispatcher(), FailingDispatcher()
    first.delivery_target_id = "recording:first"
    second.delivery_target_id = "recording:second"
    settings = settings_factory()
    outbox = AlertOutbox(store, [first, second], settings, audit, clock=clock)
    repository = make_repository(store, settings, audit, clock, outbox.channels)
    engine = CorrelationEngine(
        rules=build_rules(store, repository, settings),
        dispatchers=[first, second],
        dedup=DedupCache(store, ttl=60),
        settings=settings,
        audit=audit,
        clock=clock,
        outbox=outbox,
    )
    await engine.handle_event(CanaryEvent.model_validate(event_factory()))
    assert len(outbox.channels) == 2
    assert len(first.incidents) == 1
    assert second.calls == 1
    assert await store.outbox_pending() == 1
    recovered = RecordingDispatcher()
    recovered.delivery_target_id = second.delivery_target_id
    worker = AlertOutbox(store, [first, recovered], settings, audit, clock=clock)
    clock.advance(2)
    assert await worker.run_once() == 1
    assert len(first.incidents) == 1
    assert len(recovered.incidents) == 1


async def test_inline_and_worker_share_one_attempt(
    store: Any, settings_factory: Any, audit: Any, clock: Any, event_factory: Any
) -> None:
    entered, release = asyncio.Event(), asyncio.Event()

    class Gated(RecordingDispatcher):
        async def dispatch(self, incident: IncidentLike) -> DispatchResult:
            entered.set()
            await release.wait()
            return await super().dispatch(incident)

    dispatcher = Gated()
    settings = settings_factory()
    outbox = AlertOutbox(store, [dispatcher], settings, audit, clock=clock)
    engine = make_engine(store, settings, audit, clock, dispatcher, outbox=outbox)
    task = asyncio.create_task(engine.handle_event(CanaryEvent.model_validate(event_factory())))
    try:
        await asyncio.wait_for(entered.wait(), 2)
        assert await asyncio.wait_for(outbox.run_once(), 1) == 0
        release.set()
        await task
        assert len(dispatcher.incidents) == 1
    finally:
        release.set()
        await asyncio.gather(task, return_exceptions=True)


async def test_a_missing_hash_is_terminal_not_permanently_pending(
    store: Any, settings_factory: Any, audit: Any, audit_stream: Any, clock: Any
) -> None:
    from opencanary_correlator.storage.keys import OUTBOX_INDEX

    await store.client.zadd(OUTBOX_INDEX, {"lost": clock()})
    worker = AlertOutbox(store, [], settings_factory(), audit, clock=clock)
    await worker.run_once()
    assert await store.outbox_pending() == 0
    assert "missing_entry" in audit_stream.getvalue()


async def test_worker_cannot_send_while_enrichment_is_preparing(
    store: Any, settings_factory: Any, audit: Any, clock: Any, event_factory: Any
) -> None:
    from opencanary_correlator.enrichment.models import Enrichment, GeoInfo

    entered, release = asyncio.Event(), asyncio.Event()

    class Enricher:
        async def enrich(self, ip: str, **_: Any) -> Enrichment:
            entered.set()
            await release.wait()
            return Enrichment(geo=GeoInfo(country_code="NL", asn=123))

    settings = settings_factory()
    dispatcher = RecordingDispatcher()
    outbox = AlertOutbox(store, [dispatcher], settings, audit, clock=clock)
    engine = make_engine(store, settings, audit, clock, dispatcher, outbox=outbox)
    outbox.set_enricher(Enricher())
    task = asyncio.create_task(engine.handle_event(CanaryEvent.model_validate(event_factory())))
    try:
        await asyncio.wait_for(entered.wait(), 2)
        assert await outbox.run_once() == 0
        assert not dispatcher.incidents
        release.set()
        await task
        assert dispatcher.incidents[0].enrichment.geo.asn == 123
    finally:
        release.set()
        await asyncio.gather(task, return_exceptions=True)


async def test_crash_before_preparation_recovers_budget_without_bypass(
    store: Any, settings_factory: Any, audit: Any, clock: Any, event_factory: Any
) -> None:
    from opencanary_correlator.storage.keys import outbox_envelope_key

    settings = settings_factory(alert_budget_enabled=True, alert_budget_per_node=1)
    dispatcher = RecordingDispatcher()
    worker = AlertOutbox(store, [dispatcher], settings, audit, clock=clock)
    repository = make_repository(store, settings, audit, clock, worker.channels)
    # Neither incident gets an inline preparation (simulated process death).
    first = await repository.record(
        "ftp.login_attempt", CanaryEvent.model_validate(event_factory())
    )
    second = await repository.record(
        "ftp.login_attempt", CanaryEvent.model_validate(event_factory(src_host="10.0.0.6"))
    )
    assert await store.outbox_pending() == 0
    assert await worker.run_once() == 1
    assert len(dispatcher.incidents) == 1
    assert await worker.run_once() == 0
    states = [(await store.hgetall(outbox_envelope_key(i.key)))["state"] for i in (first, second)]
    assert sorted(states) == ["ready", "suppressed"]
    assert await store.outbox_pending() == 0


async def test_two_logtypes_share_one_virustotal_request_and_one_enrichment_per_incident(
    store: Any, settings_factory: Any, audit: Any, clock: Any, event_factory: Any
) -> None:
    """Two attack types for one IP must share the VirusTotal cache.

    With an outbox the engine delegates enrichment to it, so this test proves the
    cache is shared across incident types and that the outbox enriches once per
    incident. The separate `prepare` test covers the pre-enriched guard.
    """
    import httpx

    from opencanary_correlator.enrichment.service import IncidentEnricher
    from opencanary_correlator.enrichment.virustotal import VirusTotalClient

    payload = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 1,
                    "suspicious": 0,
                    "harmless": 10,
                    "undetected": 5,
                },
                "reputation": -2,
                "last_analysis_date": 1_793_000_000,
            }
        }
    }
    seen: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=payload)

    class CountingEnricher(IncidentEnricher):
        def __init__(self, **kwargs: Any) -> None:
            super().__init__(**kwargs)
            self.calls = 0

        async def enrich(self, src_host: str, **kwargs: Any) -> Any:
            self.calls += 1
            return await super().enrich(src_host, **kwargs)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        virustotal = VirusTotalClient(api_key="test-key", store=store, client=http)
        enricher = CountingEnricher(virustotal=virustotal)
        dispatcher = RecordingDispatcher()
        settings = settings_factory()
        outbox = AlertOutbox(store, [dispatcher], settings, audit, clock=clock)
        engine = make_engine(
            store, settings, audit, clock, dispatcher, outbox=outbox, enricher=enricher
        )

        await engine.handle_event(
            CanaryEvent.model_validate(event_factory(src_host="74.22.3.178", logtype=2000))
        )
        await engine.handle_event(
            CanaryEvent.model_validate(event_factory(src_host="74.22.3.178", logtype=14001))
        )

    assert len(seen) == 1
    assert enricher.calls == 2
    assert len(dispatcher.incidents) == 2


async def test_prepare_reuses_existing_enrichment_without_another_provider_call(
    store: Any, settings_factory: Any, audit: Any, clock: Any, event_factory: Any
) -> None:
    """An incident that already has context must not be enriched again.

    The current engine skips its own enrichment when an outbox is present, so the
    outbox is normally the only caller. This guard still matters for an incident
    handed in already enriched (a caller, a retry path or a future wiring): the
    provider context must be preserved instead of overwriting it with a second
    lookup.
    """
    from opencanary_correlator.enrichment.models import Enrichment, GeoInfo

    class CountingEnricher:
        def __init__(self) -> None:
            self.calls = 0

        async def enrich(self, src_host: str) -> Enrichment:
            self.calls += 1
            return Enrichment(geo=GeoInfo(country_code="NL"))

    settings = settings_factory()
    dispatcher = RecordingDispatcher()
    outbox = AlertOutbox(store, [dispatcher], settings, audit, clock=clock)
    enricher = CountingEnricher()
    outbox.set_enricher(enricher)  # type: ignore[arg-type]
    repository = make_repository(store, settings, audit, clock, outbox.channels)
    incident = await repository.record(
        "ftp.login_attempt", CanaryEvent.model_validate(event_factory())
    )
    assert incident is not None
    incident.enrichment = Enrichment(geo=GeoInfo(country_code="DE"))

    assert await outbox.prepare(incident)

    assert enricher.calls == 0
    assert incident.enrichment is not None
    assert incident.enrichment.geo is not None
    assert incident.enrichment.geo.country_code == "DE"


async def test_retry_preserves_enrichment_without_new_lookup(
    store: Any, settings_factory: Any, audit: Any, clock: Any, event_factory: Any
) -> None:
    from opencanary_correlator.enrichment.models import Enrichment, GeoInfo, VirusTotalReport

    class Enricher:
        calls = 0

        async def enrich(self, ip: str, **_: Any) -> Enrichment:
            self.calls += 1
            return Enrichment(
                geo=GeoInfo(country_code="NL", asn=123), virus_total=VirusTotalReport(malicious=3)
            )

    settings = settings_factory()
    failing = FailingDispatcher()
    outbox = AlertOutbox(store, [failing], settings, audit, clock=clock)
    engine = make_engine(store, settings, audit, clock, failing, outbox=outbox)
    enricher = Enricher()
    outbox.set_enricher(enricher)
    await engine.handle_event(CanaryEvent.model_validate(event_factory()))
    recovered = RecordingDispatcher()
    worker = AlertOutbox(store, [recovered], settings, audit, clock=clock)
    worker.set_enricher(enricher)
    clock.advance(2)
    assert await worker.run_once() == 1
    assert enricher.calls == 1
    assert recovered.incidents[0].enrichment.geo.asn == 123
    assert recovered.incidents[0].enrichment.virus_total.malicious == 3


async def test_retry_cannot_resurrect_a_settled_entry(store: Any, clock: Any) -> None:
    entry_id = "test#target"
    await store.enqueue_alert(entry_id, incident_key="test", channel="target", score=clock())
    old = await store.claim_alert(entry_id, now=clock(), lease=1, max_attempts=8)
    clock.advance(2)
    new = await store.claim_alert(entry_id, now=clock(), lease=60, max_attempts=8)
    assert await store.transition_alert(entry_id, owner=new, now=clock(), state="delivered")
    for state in ("ready", "dead", "delivered"):
        assert not await store.transition_alert(entry_id, owner=old, now=clock(), state=state)
    assert await store.read_alert(entry_id) is None
    assert await store.outbox_pending() == 0


async def test_slow_batch_does_not_lease_its_tail_and_backoff_uses_finish_time(
    store: Any, settings_factory: Any, audit: Any, clock: Any, event_factory: Any
) -> None:
    class Slow(FailingDispatcher):
        async def dispatch(self, incident: IncidentLike) -> DispatchResult:
            # Total batch time exceeds the nominal lease; each attempt fits.
            clock.advance(40)
            return await super().dispatch(incident)

    settings = settings_factory(outbox_lease=60)
    dispatcher = Slow()
    worker = AlertOutbox(store, [dispatcher], settings, audit, clock=clock)
    repository = make_repository(store, settings, audit, clock, worker.channels)
    for index in range(3):
        await repository.record(
            "ftp.login_attempt",
            CanaryEvent.model_validate(event_factory(src_host=f"10.0.0.{index}")),
        )
    await worker.run_once()
    assert dispatcher.calls == 3
    due = await store.due_alerts(now=clock(), limit=10)
    assert len(due) == 2  # final failure is scheduled AFTER its completion
    entries = await store.due_alerts(now=clock() + 2, limit=10)
    assert len(entries) == 3
    for entry_id in entries:
        assert (await store.read_alert(entry_id))["attempts"] == "1"


@pytest.mark.parametrize("damage", ["expired", "corrupt"])
async def test_unusable_entries_leave_pending_with_a_reason(
    store: Any, settings_factory: Any, audit: Any, audit_stream: Any, clock: Any, damage: str
) -> None:
    entry_id = "test#target"
    await store.enqueue_alert(entry_id, incident_key="test", channel="target", score=clock())
    if damage == "expired":
        clock.advance(604801)
    else:
        await store.hset_mapping(outbox_alert_key(entry_id), {"attempts": "broken"})
    worker = AlertOutbox(store, [], settings_factory(), audit, clock=clock)
    await worker.run_once()
    assert await store.outbox_pending() == 0
    assert await store.outbox_dead() == 1
    assert ("expired" if damage == "expired" else "corrupt_entry") in audit_stream.getvalue()
    assert await store.client.ttl(outbox_alert_key(entry_id)) == -1


async def test_permanent_failure_stops_and_retry_after_is_respected(
    store: Any, settings_factory: Any, audit: Any, clock: Any, event_factory: Any
) -> None:
    class Classified(FailingDispatcher):
        permanent = False

        async def dispatch(self, incident: IncidentLike) -> DispatchResult:
            return DispatchResult(
                dispatcher=self.name,
                status="error",
                detail="http_401" if self.permanent else "http_429",
                retryable=not self.permanent,
                retry_after=120,
            )

    settings = settings_factory()
    dispatcher = Classified()
    outbox = AlertOutbox(store, [dispatcher], settings, audit, clock=clock)
    engine = make_engine(store, settings, audit, clock, dispatcher, outbox=outbox)
    await engine.handle_event(CanaryEvent.model_validate(event_factory()))
    assert await store.due_alerts(now=clock() + 119, limit=10) == []
    clock.advance(121)
    dispatcher.permanent = True
    await outbox.run_once()
    assert await store.outbox_pending() == 0
    assert await store.outbox_dead() == 1


async def test_real_connector_targets_are_stable_distinct_and_secret_free(
    store: Any, settings_factory: Any
) -> None:
    from opencanary_correlator.app.channels import build_dispatchers

    settings = settings_factory(
        telegram_token="12345:old-secret",
        telegram_chat_ids=["100", "200"],
        webhook_urls=["https://example.com/a", "https://example.com/b"],
    )
    original = build_dispatchers(settings, store)
    rotated = build_dispatchers(
        settings_factory(
            telegram_token="12345:new-secret",
            telegram_chat_ids=["200", "100"],
            webhook_urls=["https://example.com/b", "https://example.com/a"],
        ),
        store,
    )
    try:
        ids = {d.target_id for d in original}
        assert len(ids) == 4
        assert ids == {d.target_id for d in rotated}
        assert all(len(i.split(":")[1]) == 64 for i in ids)
        assert all("secret" not in i and "example.com" not in i for i in ids)
    finally:
        for dispatcher in original + rotated:
            await dispatcher.aclose()


async def test_legacy_outbox_is_visible_but_never_delivered_or_modified(
    store: Any, settings_factory: Any, audit: Any, audit_stream: Any, clock: Any
) -> None:
    from opencanary_correlator.storage.keys import LEGACY_OUTBOX_INDEX

    await store.client.zadd(LEGACY_OUTBOX_INDEX, {"old#telegram": clock()})
    dispatcher = RecordingDispatcher()
    outbox = AlertOutbox(store, [dispatcher], settings_factory(), audit, clock=clock)
    await outbox.start()
    try:
        await outbox.run_once()
    finally:
        await outbox.stop()
    assert not dispatcher.incidents
    assert await store.client.zcard(LEGACY_OUTBOX_INDEX) == 1
    assert "outbox_legacy_quarantined" in audit_stream.getvalue()


async def test_preparation_lease_fences_stale_budget_decision(
    store: Any, settings_factory: Any, audit: Any, clock: Any, event_factory: Any
) -> None:
    from opencanary_correlator.storage.keys import budget_global_key

    settings = settings_factory(alert_budget_enabled=True)
    repository = make_repository(store, settings, audit, clock, ("recording",))
    incident = await repository.record(
        "ftp.login_attempt", CanaryEvent.model_validate(event_factory())
    )
    first = await store.claim_alert(
        incident.key, now=clock(), lease=1, max_attempts=8, preparing=True
    )
    clock.advance(2)
    second = await store.claim_alert(
        incident.key, now=clock(), lease=60, max_attempts=8, preparing=True
    )
    kwargs = dict(
        now=clock(),
        enrichment="null",
        budget_enabled=True,
        node_id=incident.node_id,
        window=3600,
        per_node=20,
        global_limit=200,
    )
    assert await store.prepare_alerts(incident.key, owner=first, **kwargs) == ""
    assert await store.prepare_alerts(incident.key, owner=second, **kwargs) == "ready"
    assert await store.prepare_alerts(incident.key, owner=second, **kwargs) == ""
    assert await store.get_value(budget_global_key(int(clock() - clock() % 3600))) == "1"
    assert await store.outbox_pending() == 1


async def test_http_outbox_returns_retry_after_without_sleeping_inside_attempt(
    store: Any, settings_factory: Any, audit: Any, clock: Any, event_factory: Any
) -> None:
    import httpx

    from opencanary_correlator.connectors.dispatchers.webhook import WebhookDispatcher

    requests = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(429, headers={"Retry-After": "120"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        dispatcher = WebhookDispatcher(url="https://example.com/hook", client=client)
        settings = settings_factory()
        outbox = AlertOutbox(store, [dispatcher], settings, audit, clock=clock)
        engine = make_engine(store, settings, audit, clock, dispatcher, outbox=outbox)
        await asyncio.wait_for(engine.handle_event(CanaryEvent.model_validate(event_factory())), 2)
        assert len(requests) == 1
        assert await store.due_alerts(now=clock() + 119, limit=10) == []
        assert len(await store.due_alerts(now=clock() + 120, limit=10)) == 1


@pytest.mark.parametrize("channel", ["telegram", "webhook"])
async def test_concrete_targets_retry_only_the_failed_destination(
    store: Any, settings_factory: Any, audit: Any, clock: Any, event_factory: Any, channel: str
) -> None:
    import json

    import httpx

    from opencanary_correlator.connectors.dispatchers.telegram import TelegramDispatcher
    from opencanary_correlator.connectors.dispatchers.webhook import WebhookDispatcher

    calls = []
    failing = [True]

    async def handler(request: httpx.Request) -> httpx.Response:
        target = (
            json.loads(request.content)["chat_id"] if channel == "telegram" else request.url.path
        )
        calls.append(target)
        return httpx.Response(503 if failing[0] and target in {"200", "/b"} else 200)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:

        def build() -> list[BaseDispatcher]:
            if channel == "telegram":
                return [
                    TelegramDispatcher(token="12345:test", chat_id=t, client=client)
                    for t in ("100", "200")
                ]
            return [
                WebhookDispatcher(url=f"https://example.com/{t}", client=client) for t in ("a", "b")
            ]

        dispatchers = build()
        settings = settings_factory()
        outbox = AlertOutbox(store, dispatchers, settings, audit, clock=clock)
        repository = make_repository(store, settings, audit, clock, outbox.channels)
        incident = await repository.record(
            "ftp.login_attempt", CanaryEvent.model_validate(event_factory())
        )
        assert await outbox.prepare(incident)
        await asyncio.gather(*(outbox.deliver_inline(incident, d) for d in dispatchers))
        assert len(calls) == 2
        assert await store.outbox_pending() == 1
        failing[0] = False
        clock.advance(2)
        worker = AlertOutbox(store, build(), settings, audit, clock=clock)
        assert await worker.run_once() == 1
        assert calls.count("100" if channel == "telegram" else "/a") == 1
        assert calls.count("200" if channel == "telegram" else "/b") == 2
        assert await store.outbox_pending() == 0


@pytest.mark.parametrize("damage", ["missing_incident", "expired_preparation"])
async def test_preparation_failure_terminates_all_targets_atomically(
    store: Any, settings_factory: Any, audit: Any, clock: Any, event_factory: Any, damage: str
) -> None:
    from opencanary_correlator.storage.keys import outbox_envelope_key

    repository = make_repository(store, settings_factory(), audit, clock, ("a", "b"))
    incident = await repository.record(
        "ftp.login_attempt", CanaryEvent.model_validate(event_factory())
    )
    if damage == "missing_incident":
        await store.delete(incident.key)
    else:
        clock.advance(604801)
    worker = AlertOutbox(store, [], settings_factory(), audit, clock=clock)
    await worker.run_once()
    assert await store.due_alerts(now=clock(), limit=10, preparing=True) == []
    assert (await store.hgetall(outbox_envelope_key(incident.key)))["state"] == "dead"
    for target in ("a", "b"):
        assert (await store.read_alert(f"{incident.key}#{target}"))["state"] == "dead"
    assert await worker.run_once() == 0


def test_the_backoff_grows_and_then_holds() -> None:
    assert BACKOFF_SECONDS == tuple(sorted(BACKOFF_SECONDS))
    assert BACKOFF_SECONDS[0] == pytest.approx(1.0)
