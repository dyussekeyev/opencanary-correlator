"""HTTP request rule: log types 3000/3002/3003 become one `http.request` incident."""

from __future__ import annotations

import json
from typing import Any

from opencanary_correlator.connectors.base import BaseDispatcher, DispatchResult, IncidentLike
from opencanary_correlator.constants import INCIDENT_KEY_PREFIX, LogType
from opencanary_correlator.core.engine import CorrelationEngine
from opencanary_correlator.core.incident import Incident, IncidentRepository
from opencanary_correlator.core.rules import build_rules
from opencanary_correlator.core.rules.http import HttpRequestRule
from opencanary_correlator.core.windows import DedupCache
from opencanary_correlator.schemas import CanaryEvent

GET_LOG_DATA: dict[str, Any] = {
    "HOST": "canary-1",
    "PATH": "/admin",
    "USERAGENT": "curl/8.4.0",
}


class RecordingDispatcher(BaseDispatcher):
    """Dispatcher that records the incidents it received."""

    name = "recording"

    def __init__(self) -> None:
        self.incidents: list[Incident] = []

    async def dispatch(self, incident: IncidentLike) -> DispatchResult:
        assert isinstance(incident, Incident)
        self.incidents.append(incident)
        return DispatchResult(dispatcher=self.name, status="success")


def http_event(
    event_factory: Any, *, logtype: int, logdata: dict[str, Any] | None = None
) -> CanaryEvent:
    payload = GET_LOG_DATA if logdata is None else logdata
    return CanaryEvent.model_validate(event_factory(logtype=logtype, dst_port=80, logdata=payload))


def make_engine(
    store: Any, settings: Any, audit: Any, clock: Any, dispatcher: RecordingDispatcher
) -> CorrelationEngine:
    repository = IncidentRepository(store, settings, audit, clock=clock)
    return CorrelationEngine(
        rules=build_rules(store, repository, settings),
        dispatchers=[dispatcher],
        dedup=DedupCache(store, ttl=settings.dedup_ttl),
        settings=settings,
        audit=audit,
        clock=clock,
    )


async def test_http_get_creates_a_http_request_incident(
    store: Any, settings_factory: Any, audit: Any, clock: Any, event_factory: Any
) -> None:
    repository = IncidentRepository(store, settings_factory(), audit, clock=clock)
    rule = HttpRequestRule(repository)
    event = http_event(event_factory, logtype=int(LogType.LOG_HTTP_GET))

    assert rule.matches(event)
    incidents = await rule.apply(event, now=clock.now)

    assert len(incidents) == 1
    incident = incidents[0]
    assert incident.INCIDENT_NAME == "http.request"
    assert incident.key.startswith(INCIDENT_KEY_PREFIX["http.request"])
    assert incident.logtype == int(LogType.LOG_HTTP_GET)
    assert incident.src_host == "10.0.0.5"


def test_the_rule_covers_requests_but_not_login_attempts(
    store: Any, settings_factory: Any, audit: Any, clock: Any, event_factory: Any
) -> None:
    rule = HttpRequestRule(IncidentRepository(store, settings_factory(), audit, clock=clock))

    covered = [
        int(LogType.LOG_HTTP_GET),
        int(LogType.LOG_HTTP_UNIMPLEMENTED_METHOD),
        int(LogType.LOG_HTTP_REDIRECT),
    ]
    for logtype in covered:
        assert rule.matches(http_event(event_factory, logtype=logtype)), logtype

    for logtype in (int(LogType.LOG_HTTP_POST_LOGIN_ATTEMPT), int(LogType.LOG_PORT_SYN)):
        assert not rule.matches(http_event(event_factory, logtype=logtype)), logtype


async def test_http_get_is_no_longer_audited_as_unrouted(
    store: Any, settings_factory: Any, audit: Any, audit_stream: Any, clock: Any, event_factory: Any
) -> None:
    dispatcher = RecordingDispatcher()
    engine = make_engine(store, settings_factory(), audit, clock, dispatcher)

    await engine.handle_event(http_event(event_factory, logtype=int(LogType.LOG_HTTP_GET)))

    actions = [json.loads(line)["action"] for line in audit_stream.getvalue().splitlines()]
    assert "event_unrouted" not in actions
    assert "alert_dispatch" in actions
    assert [incident.INCIDENT_NAME for incident in dispatcher.incidents] == ["http.request"]


async def test_http_login_attempt_keeps_its_own_incident(
    store: Any, settings_factory: Any, audit: Any, clock: Any, event_factory: Any
) -> None:
    dispatcher = RecordingDispatcher()
    engine = make_engine(store, settings_factory(), audit, clock, dispatcher)

    await engine.handle_event(
        http_event(
            event_factory,
            logtype=int(LogType.LOG_HTTP_POST_LOGIN_ATTEMPT),
            logdata={"USERNAME": "admin", "PASSWORD": "hunter2", "PATH": "/login"},
        )
    )

    assert [incident.INCIDENT_NAME for incident in dispatcher.incidents] == ["http.login_attempt"]


async def test_requests_from_one_host_merge_into_one_alert(
    store: Any, settings_factory: Any, audit: Any, clock: Any, event_factory: Any
) -> None:
    dispatcher = RecordingDispatcher()
    engine = make_engine(store, settings_factory(), audit, clock, dispatcher)

    await engine.handle_event(http_event(event_factory, logtype=int(LogType.LOG_HTTP_GET)))
    clock.advance(1)
    await engine.handle_event(
        http_event(
            event_factory,
            logtype=int(LogType.LOG_HTTP_UNIMPLEMENTED_METHOD),
            logdata={"HOST": "canary-1", "PATH": "/wp-login.php"},
        )
    )

    # Only the incident that was created is alerted; the second request merged
    # into it inside the horizon, which is what bounds scanner alert volume.
    assert len(dispatcher.incidents) == 1
    stored = await store.hgetall(dispatcher.incidents[0].key)
    assert stored["events_count"] == "2"
    assert len(json.loads(stored["logdata"])) == 2
    # The incident keeps the log type of the event that created it, like every
    # other merged incident.
    assert stored["logtype"] == str(int(LogType.LOG_HTTP_GET))
