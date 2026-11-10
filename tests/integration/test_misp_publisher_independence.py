"""The MISP publisher is independent of the alert outbox and the alert budget.

Both scenarios use the real engine, the real ``AlertOutbox`` and the real
``MispPublisher`` over a fakeredis store; only the MISP HTTP transport and (in
the outbox scenario) the Redis connection used by the outbox are substituted.
The point is the wiring, not the publisher's own unit behaviour: an observation
must still reach MISP when the alert path is broken or rationed.
"""

from __future__ import annotations

import io
import json
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import unquote

import httpx
import pytest
from redis.asyncio import Redis
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import TimeoutError as RedisTimeoutError

from opencanary_correlator.audit import AuditLogger
from opencanary_correlator.connectors.base import BaseDispatcher, DispatchResult, IncidentLike
from opencanary_correlator.connectors.publishers.misp import MispClient
from opencanary_correlator.connectors.publishers.misp.publisher import MispPublisher
from opencanary_correlator.connectors.publishers.misp.queue import MispObservationQueue
from opencanary_correlator.core.engine import CorrelationEngine
from opencanary_correlator.core.incident import Incident, IncidentRepository
from opencanary_correlator.core.outbox import AlertOutbox
from opencanary_correlator.core.rules import build_rules
from opencanary_correlator.core.windows import DedupCache
from opencanary_correlator.schemas import CanaryEvent
from opencanary_correlator.storage.redis_store import RedisStore

pytestmark = pytest.mark.integration

ENGINE_NOW = datetime(2026, 10, 24, 10, 0, tzinfo=UTC)
PUBLISHED_AT = datetime(2026, 10, 25, 1, 0, tzinfo=UTC)
FIRST_ATTACKER = "93.184.216.34"
SECOND_ATTACKER = "93.184.216.35"


class RecordingDispatcher(BaseDispatcher):
    """Dispatcher that records the incidents the budget allowed through."""

    name = "recording"

    def __init__(self) -> None:
        self.incidents: list[Incident] = []

    async def dispatch(self, incident: IncidentLike) -> DispatchResult:
        assert isinstance(incident, Incident)
        self.incidents.append(incident)
        return DispatchResult(dispatcher=self.name, status="success")


class FakeMisp:
    """Minimal MISP Automation API double that records writes."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []
        self.attribute_values: list[str] = []

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)

    def _handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        self.calls.append((request.method, path))
        if path == "/warninglists/index":
            return httpx.Response(
                200, json={"Warninglists": [{"id": "1", "enabled": True}]}, request=request
            )
        if path == "/warninglists/checkValue":
            return httpx.Response(200, json={}, request=request)
        if path == "/attributes/restSearch":
            return httpx.Response(200, json={"response": {"Attribute": []}}, request=request)
        if request.method == "GET" and path.startswith("/events/view/"):
            return httpx.Response(404, json={"errors": "not found"}, request=request)
        if request.method == "GET" and path.startswith("/tags/search/"):
            name = unquote(path.rsplit("/", 1)[-1])
            return httpx.Response(200, json={"Tag": [{"id": "1", "name": name}]}, request=request)
        if path == "/events/add":
            body = json.loads(request.read())
            return httpx.Response(
                200, json={"Event": {"id": "900", "uuid": body["Event"]["uuid"]}}, request=request
            )
        if path.startswith("/attributes/add/"):
            body = json.loads(request.read())
            self.attribute_values.append(body["Attribute"]["value"])
            return httpx.Response(200, json={"Attribute": {"id": "901"}}, request=request)
        if path.startswith("/events/addTag/"):
            return httpx.Response(200, json={}, request=request)
        if path == "/sightings/add":
            return httpx.Response(200, json={"Sighting": {"id": "1"}}, request=request)
        if path.startswith("/events/publish/"):
            raise AssertionError("draft mode must never call the publish endpoint")
        raise AssertionError(f"unexpected MISP call: {request.method} {path}")


def _audit_actions(stream: io.StringIO) -> list[str]:
    return [json.loads(line)["action"] for line in stream.getvalue().splitlines()]


def _settings(settings_factory: Callable[..., Any], **overrides: Any) -> Any:
    return settings_factory(
        misp_url="https://misp.test",
        misp_api_key="integration-secret",
        misp_publish_grace=0.0,
        **overrides,
    )


def _publisher(
    settings: Any,
    store: RedisStore,
    audit: AuditLogger,
    queue: MispObservationQueue,
    fake: FakeMisp,
) -> tuple[MispPublisher, httpx.AsyncClient]:
    http = httpx.AsyncClient(transport=fake.transport())
    client = MispClient(url="https://misp.test", api_key="integration-secret", client=http)
    publisher = MispPublisher(
        settings=settings,
        store=store,
        audit=audit,
        client=client,
        queue=queue,
        clock=lambda: PUBLISHED_AT,
    )
    return publisher, http


def _engine(
    store: RedisStore,
    settings: Any,
    audit: AuditLogger,
    dispatcher: RecordingDispatcher,
    outbox: AlertOutbox | None,
    publisher: MispPublisher,
    clock: Callable[[], float],
) -> CorrelationEngine:
    repository = IncidentRepository(
        store,
        settings,
        audit,
        clock=clock,
        alert_channels=outbox.channels if outbox is not None else (),
    )
    return CorrelationEngine(
        rules=build_rules(store, repository, settings),
        dispatchers=[dispatcher],
        dedup=DedupCache(store, ttl=settings.dedup_ttl),
        settings=settings,
        audit=audit,
        clock=clock,
        outbox=outbox,
        publishers=[publisher],
    )


async def test_publisher_publishes_when_the_outbox_is_unavailable(
    fake_redis: Any,
    settings_factory: Callable[..., Any],
    event_factory: Callable[..., dict[str, Any]],
    free_tcp_port: int,
) -> None:
    store = RedisStore(fake_redis)
    settings = _settings(settings_factory)
    audit_stream = io.StringIO()
    audit = AuditLogger("misp-independence", stream=audit_stream)
    dispatcher = RecordingDispatcher()
    engine_clock = lambda: ENGINE_NOW.timestamp()  # noqa: E731 - a fixed test clock

    # A refused Redis connection is a real unavailable outbox: the claim script
    # cannot even reach the server.
    refused = Redis(
        host="127.0.0.1", port=free_tcp_port, socket_connect_timeout=1.0, socket_timeout=1.0
    )
    outbox = AlertOutbox(RedisStore(refused), [dispatcher], settings, audit, clock=engine_clock)
    queue = MispObservationQueue(store)
    fake = FakeMisp()
    publisher, http = _publisher(settings, store, audit, queue, fake)
    engine = _engine(store, settings, audit, dispatcher, outbox, publisher, engine_clock)
    event = CanaryEvent.model_validate(event_factory(src_host=FIRST_ATTACKER))

    try:
        # Depending on the OS the refused connection surfaces immediately or
        # as a connect timeout; both mean the outbox cannot be reached.
        with pytest.raises((RedisConnectionError, RedisTimeoutError)):
            await engine.handle_event(event)

        # The alert path failed before any delivery, but the observation is
        # already durable in the publisher's own queue.
        assert dispatcher.incidents == []
        assert await queue.pending_count() == 1

        assert await publisher.run_once() == 1
        assert fake.attribute_values == [FIRST_ATTACKER]
        assert await queue.pending_count() == 0
        actions = _audit_actions(audit_stream)
        assert "misp_window_published" in actions
        assert not any(action.startswith("alert_") for action in actions)
    finally:
        await publisher.aclose()
        await http.aclose()
        await refused.aclose()


async def test_budget_suppression_does_not_stop_misp_publication(
    fake_redis: Any,
    settings_factory: Callable[..., Any],
    event_factory: Callable[..., dict[str, Any]],
) -> None:
    store = RedisStore(fake_redis)
    settings = _settings(
        settings_factory,
        alert_budget_enabled=True,
        alert_budget_per_node=1,
        alert_budget_global=1,
    )
    audit_stream = io.StringIO()
    audit = AuditLogger("misp-independence", stream=audit_stream)
    dispatcher = RecordingDispatcher()
    engine_clock = lambda: ENGINE_NOW.timestamp()  # noqa: E731 - a fixed test clock
    outbox = AlertOutbox(store, [dispatcher], settings, audit, clock=engine_clock)
    queue = MispObservationQueue(store)
    fake = FakeMisp()
    publisher, http = _publisher(settings, store, audit, queue, fake)
    engine = _engine(store, settings, audit, dispatcher, outbox, publisher, engine_clock)

    try:
        await engine.handle_event(
            CanaryEvent.model_validate(event_factory(src_host=FIRST_ATTACKER))
        )
        # The node's single budget slot is spent, so this alert reaches no
        # channel; the observation must still be published.
        await engine.handle_event(
            CanaryEvent.model_validate(event_factory(src_host=SECOND_ATTACKER))
        )

        assert len(dispatcher.incidents) == 1
        actions = _audit_actions(audit_stream)
        assert "alert_suppressed" in actions

        assert await publisher.run_once() == 1
        assert set(fake.attribute_values) == {FIRST_ATTACKER, SECOND_ATTACKER}
        assert await queue.pending_count() == 0
        assert "misp_window_published" in _audit_actions(audit_stream)
    finally:
        await publisher.aclose()
        await http.aclose()
