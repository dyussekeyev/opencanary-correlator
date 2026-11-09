"""Focused tests for the MISP publisher's pure and network-facing pieces."""

from __future__ import annotations

import io
from datetime import UTC, datetime, timedelta
from uuid import UUID

import httpx
import pytest

from opencanary_correlator.audit import AuditLogger
from opencanary_correlator.connectors.publishers.misp import (
    MispAttribute,
    MispAuthError,
    MispClient,
    MispClientError,
    MispEvent,
    MispEventBuilder,
    MispExistingAttribute,
    MispExistingEvent,
    MispObservation,
    MispObservationQueue,
    MispPublisher,
    MispWindow,
    observation_from_incident,
    window_bounds,
)
from opencanary_correlator.enrichment.models import Enrichment, GeoInfo

START = datetime(2026, 11, 9, tzinfo=UTC)


def _observation(
    ip: str = "8.8.8.8",
    *,
    count: int = 3,
    service: str = "ssh.login_attempt",
    port: int = 22,
) -> MispObservation:
    return MispObservation(
        ip=ip,
        first_seen=START + timedelta(minutes=1),
        last_seen=START + timedelta(minutes=2),
        count=count,
        services={service: count},
        ports={port: count},
    )


def _event() -> MispEvent:
    return MispEvent(
        uuid=UUID("0f5f7d6b-74b7-4b1f-9d1c-ee0f8f1c2a10"),
        info="OpenCanary honeypot observations 2026-11-09 UTC (1 source addresses)",
        date="2026-11-09",
        distribution="0",
        attributes=(),
        tags=("tlp:amber",),
    )


def test_observation_uses_public_address_and_never_sends_raw_logdata(
    incident_factory: object,
) -> None:
    incident = incident_factory(  # type: ignore[operator]
        src_host="8.8.8.8",
        dst_port=22,
        created=int(START.timestamp()),
        events_list=f"{int(START.timestamp())},{int((START + timedelta(seconds=5)).timestamp())}",
        events_count=4,
        logdata='[{"PASSWORD": "hunter2"}]',
    )
    observation = observation_from_incident(incident)

    assert observation is not None
    assert observation.ip == "8.8.8.8"
    assert observation.count == 4
    assert observation.first_seen == START
    assert observation.last_seen == START + timedelta(seconds=5)
    assert observation.services == {"ftp.login_attempt": 4}
    assert observation.ports == {22: 4}

    incident.enrichment = Enrichment(
        geo=GeoInfo(country_code="KZ", country="Kazakhstan", asn=202958, as_org="Hoster.KZ")
    )
    enriched = observation_from_incident(incident)
    assert enriched is not None
    assert enriched.country_code == "KZ"
    assert enriched.asn == 202958
    assert enriched.as_org == "Hoster.KZ"


@pytest.mark.parametrize(
    "address",
    ["10.0.0.5", "127.0.0.1", "192.0.2.10", "2001:db8::1", "198.51.100.7", "not-an-ip"],
)
def test_observation_refuses_non_global_or_invalid_addresses(
    incident_factory: object, address: str
) -> None:
    incident = incident_factory(src_host=address)  # type: ignore[operator]
    assert observation_from_incident(incident) is None


def test_observation_refuses_an_explicitly_protected_honeypot_address(
    incident_factory: object,
) -> None:
    incident = incident_factory(src_host="8.8.8.8")  # type: ignore[operator]
    assert observation_from_incident(incident, protected_addresses=frozenset({"8.8.8.8"})) is None


def test_builder_is_deterministic_and_flags_only_auth_services_above_threshold() -> None:
    builder = MispEventBuilder(
        namespace="opencanary",
        distribution=0,
        tlp="amber",
        pap="amber",
        to_ids_types=frozenset({"ssh.login_attempt"}),
        to_ids_min_events=3,
    )
    window = MispWindow(
        start=START,
        end=START + timedelta(days=1),
        observations=(_observation(), _observation("1.1.1.1", count=2)),
    )

    first = builder.build(window)
    second = builder.build(window)

    assert first.uuid == second.uuid
    assert first.date == "2026-11-09"
    assert first.distribution == "0"
    assert first.tags == (
        "tlp:amber",
        "pap:amber",
        'misp:confidence-level="rarely-confident"',
        "honeypot",
    )
    assert len(first.attributes) == 2
    by_ip = {item.value: item for item in first.attributes}
    assert by_ip["8.8.8.8"].to_ids is True
    assert by_ip["1.1.1.1"].to_ids is False
    second_by_ip = {item.value: item for item in second.attributes}
    assert by_ip["8.8.8.8"].uuid == second_by_ip["8.8.8.8"].uuid
    assert "hunter2" not in by_ip["8.8.8.8"].comment


def test_builder_includes_geo_and_network_in_the_attribute_comment() -> None:
    observation = _observation().model_copy(
        update={"country_code": "KZ", "country": "Kazakhstan", "asn": 202958, "as_org": "Hoster.KZ"}
    )
    event = MispEventBuilder(namespace="opencanary").build(
        MispWindow(start=START, end=START + timedelta(days=1), observations=(observation,))
    )
    assert "Country/network: KZ, AS202958 Hoster.KZ" in event.attributes[0].comment


def test_builder_distribution_four_carries_the_sharing_group() -> None:
    event = MispEventBuilder(namespace="opencanary", distribution=4, sharing_group_id=7).build(
        MispWindow(start=START, end=START + timedelta(days=1), observations=(_observation(),))
    )
    assert event.distribution == "4"
    assert event.sharing_group_id == "7"


def test_window_bounds_are_fixed_utc_windows() -> None:
    start, end = window_bounds(START + timedelta(hours=23, minutes=59), 24 * 3600)
    assert start == START
    assert end == START + timedelta(days=1)


def _client(handler: object, **kwargs: object) -> MispClient:
    transport = httpx.MockTransport(handler)  # type: ignore[arg-type]
    http = httpx.AsyncClient(transport=transport)
    return MispClient(
        url="https://misp.test",
        api_key="test-key",
        client=http,
        **kwargs,  # type: ignore[arg-type]
    )


async def test_client_adds_event_and_attribute_with_automation_header() -> None:
    calls: list[tuple[str, str, dict[str, object] | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = request.read()
        calls.append(
            (
                request.method,
                request.url.path,
                __import__("json").loads(body) if body else None,
            )
        )
        assert request.headers["Authorization"] == "test-key"
        if request.url.path == "/events/add":
            return httpx.Response(
                200,
                json={"Event": {"id": "42", "uuid": str(_event().uuid)}},
                request=request,
            )
        return httpx.Response(200, json={"Attribute": {"id": "9001"}}, request=request)

    client = _client(handler)
    event_id, event_uuid = await client.add_event(_event())
    attribute = MispAttribute(
        uuid=UUID("8f5f7d6b-74b7-4b1f-9d1c-ee0f8f1c2a10"),
        value="8.8.8.8",
        to_ids=True,
        first_seen="2026-11-09T00:01:00Z",
        last_seen="2026-11-09T00:02:00Z",
        comment="fixed",
    )
    assert await client.add_attribute(event_id, attribute) == 9001
    assert event_id == 42
    assert event_uuid == _event().uuid
    assert calls[0][1] == "/events/add"
    assert calls[1][1] == "/attributes/add/42"
    assert calls[0][2] == {"Event": _event().payload()}
    assert calls[1][2] == {"Attribute": attribute.payload()}


async def test_client_turns_auth_failure_and_redirect_into_safe_errors() -> None:
    def unauthorized(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"errors": "nope"}, request=request)

    with pytest.raises(MispAuthError):
        await _client(unauthorized).add_event(_event())

    def redirect(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "https://evil.test/"}, request=request)

    with pytest.raises(MispClientError) as caught:
        await _client(redirect).add_event(_event())
    assert caught.value.status_code == 302
    assert "evil" not in str(caught.value)


async def test_client_reads_empty_warninglist_and_mapping_shapes() -> None:
    def empty(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[], request=request)

    client = _client(empty)
    assert await client.check_warninglists(["8.8.8.8"]) == {}

    def mapped(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"8.8.8.8": [{"id": "1", "name": "Public DNS"}]},
            request=request,
        )

    assert await _client(mapped).check_warninglists(["8.8.8.8"]) == {"8.8.8.8": ("Public DNS",)}


async def test_client_finds_exact_ip_attributes_and_sends_sighting_values() -> None:
    calls: list[tuple[str, dict[str, object]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = __import__("json").loads(request.read())
        calls.append((request.url.path, body))
        if request.url.path == "/attributes/restSearch":
            return httpx.Response(
                200,
                json={
                    "response": {
                        "Attribute": [
                            {"id": "11", "value": "8.8.8.8", "type": "ip-src"},
                            {"id": "12", "value": "8.8.8.80", "type": "ip-src"},
                            {"id": "13", "value": "8.8.8.8", "type": "ip-dst"},
                        ]
                    }
                },
                request=request,
            )
        return httpx.Response(
            200,
            json={"Sighting": {"id": "99"}},
            request=request,
        )

    client = _client(handler)
    found = await client.find_ip_attributes(["8.8.8.8"])
    assert found == {"8.8.8.8": (MispExistingAttribute(id=11, value="8.8.8.8"),)}
    assert calls[0] == (
        "/attributes/restSearch",
        {"value": "8.8.8.8", "type": "ip-src", "limit": 1000, "page": 1},
    )
    assert await client.add_sighting(["8.8.8.8"]) == 99
    assert calls[1] == (
        "/sightings/add",
        {"values": ["8.8.8.8"], "filters": {"type": "ip-src"}},
    )


async def test_client_reads_event_details_and_deletes_it() -> None:
    calls: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path))
        if request.method == "GET":
            return httpx.Response(
                200,
                json={
                    "Event": {
                        "id": "42",
                        "uuid": str(_event().uuid),
                        "distribution": "0",
                        "published": False,
                    },
                    "Attribute": [
                        {"value": "8.8.8.8", "to_ids": False},
                    ],
                    "Tag": [{"name": "tlp:amber"}],
                },
                request=request,
            )
        return httpx.Response(200, json={"saved": True}, request=request)

    client = _client(handler)
    found = await client.find_event(_event().uuid)
    assert found is not None
    assert found.id == 42
    assert found.distribution == "0"
    assert found.attribute_values == frozenset({"8.8.8.8"})
    assert found.to_ids_values == frozenset()
    assert found.tags == frozenset({"tlp:amber"})
    assert found.published is False
    await client.delete_event(42)
    assert calls == [("GET", f"/events/view/{_event().uuid}"), ("DELETE", "/events/delete/42")]


async def test_client_finds_missing_event_and_tag_as_none() -> None:
    def missing(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, request=request)

    client = _client(missing)
    assert await client.find_event(_event().uuid) is None
    assert await client.search_tag("tlp:amber") is None


async def test_queue_merges_duplicate_addresses_and_acknowledges(store: object) -> None:
    queue = MispObservationQueue(store)  # type: ignore[arg-type]
    first = _observation(count=2)
    second = _observation(count=3, port=2222).model_copy(
        update={"country_code": "KZ", "asn": 202958}
    )
    assert await queue.enqueue(START, START + timedelta(days=1), first) is True
    assert await queue.enqueue(START, START + timedelta(days=1), second) is True
    assert await queue.pending(START + timedelta(days=1)) == [START]
    merged = await queue.read(START)
    assert len(merged) == 1
    assert merged[0].count == 5
    assert merged[0].ports == {22: 2, 2222: 3}
    assert merged[0].country_code == "KZ"
    assert merged[0].asn == 202958
    await queue.ack(START)
    assert await queue.pending_count() == 0
    assert await queue.read(START) == []


class FakeMisp:
    def __init__(
        self,
        *,
        enabled: int = 1,
        tag: str | None = "1",
        known: dict[str, tuple[MispExistingAttribute, ...]] | None = None,
        existing_event: MispExistingEvent | None = None,
    ) -> None:
        self.enabled = enabled
        self.tag = tag
        self.known = known or {}
        self.existing_event = existing_event
        self.created: MispEvent | None = None
        self.attributes: list[MispAttribute] = []
        self.tags: list[str] = []
        self.sightings: list[str] = []
        self.published = False
        self.publish_calls = 0

    async def search_tag(self, name: str) -> str | None:
        return self.tag

    async def warninglists_enabled(self) -> int:
        return self.enabled

    async def check_warninglists(self, values: list[str]) -> dict[str, tuple[str, ...]]:
        return {}

    async def find_event(self, event_uuid: UUID) -> MispExistingEvent | None:
        return self.existing_event

    async def find_ip_attributes(
        self, values: list[str]
    ) -> dict[str, tuple[MispExistingAttribute, ...]]:
        return {value: self.known[value] for value in values if value in self.known}

    async def add_sighting(self, values: list[str]) -> int:
        self.sightings.extend(values)
        return len(values)

    async def add_event(self, event: MispEvent) -> tuple[int, UUID]:
        self.created = event
        return 42, event.uuid

    async def add_attribute(self, event_id: int, attribute: MispAttribute) -> int:
        self.attributes.append(attribute)
        return 1

    async def add_event_tag(self, event_id: int, tag_id: str) -> None:
        self.tags.append(tag_id)

    async def publish_event(self, event_id: int) -> None:
        self.publish_calls += 1
        self.published = True

    async def aclose(self) -> None:
        return None


def _publisher(store: object, settings: object, client: FakeMisp) -> MispPublisher:
    return MispPublisher(
        settings=settings,  # type: ignore[arg-type]
        store=store,  # type: ignore[arg-type]
        audit=AuditLogger("test", stream=io.StringIO()),
        client=client,  # type: ignore[arg-type]
        clock=lambda: START + timedelta(days=1, seconds=1),
    )


async def test_publisher_builds_a_draft_and_acknowledges_only_after_attributes(
    store: object, settings_factory: object, incident_factory: object
) -> None:
    settings = settings_factory(  # type: ignore[operator]
        misp_enabled=True,
        misp_url="https://misp.test",
        misp_api_key="secret",
        misp_publish_grace=0,
        misp_publish_mode="draft",
    )
    incident = incident_factory(  # type: ignore[operator]
        src_host="8.8.8.8",
        created=int(START.timestamp()),
        events_list=str(int(START.timestamp())),
        events_count=3,
    )
    client = FakeMisp()
    publisher = _publisher(store, settings, client)

    await publisher.observe(incident)
    assert await publisher.run_once() == 1

    assert client.created is not None
    assert client.created.attributes == ()
    assert len(client.attributes) == 1
    assert client.attributes[0].value == "8.8.8.8"
    assert client.attributes[0].to_ids is True
    assert client.tags == ["1", "1", "1", "1"]
    assert client.publish_calls == 0
    assert publisher._queue is not None


async def test_publisher_sights_known_address_and_creates_no_event(
    store: object, settings_factory: object, incident_factory: object
) -> None:
    settings = settings_factory(  # type: ignore[operator]
        misp_enabled=True,
        misp_url="https://misp.test",
        misp_api_key="secret",
        misp_publish_grace=0,
    )
    incident = incident_factory(  # type: ignore[operator]
        src_host="8.8.8.8",
        created=int(START.timestamp()),
        events_list=str(int(START.timestamp())),
        events_count=3,
    )
    known = {"8.8.8.8": (MispExistingAttribute(id=11, value="8.8.8.8"),)}
    client = FakeMisp(known=known)
    publisher = _publisher(store, settings, client)

    await publisher.observe(incident)
    assert await publisher.run_once() == 1

    assert client.created is None
    assert client.attributes == []
    assert client.sightings == ["8.8.8.8"]
    assert await publisher._queue.pending_count() == 0


async def test_publisher_creates_event_only_for_new_addresses(
    store: object, settings_factory: object, incident_factory: object
) -> None:
    settings = settings_factory(  # type: ignore[operator]
        misp_enabled=True,
        misp_url="https://misp.test",
        misp_api_key="secret",
        misp_publish_grace=0,
    )
    known = {"8.8.8.8": (MispExistingAttribute(id=11, value="8.8.8.8"),)}
    client = FakeMisp(known=known)
    publisher = _publisher(store, settings, client)
    for address in ("8.8.8.8", "1.1.1.1"):
        incident = incident_factory(  # type: ignore[operator]
            src_host=address,
            created=int(START.timestamp()),
            events_list=str(int(START.timestamp())),
            events_count=3,
        )
        await publisher.observe(incident)

    assert await publisher.run_once() == 1
    assert client.created is not None
    assert [item.value for item in client.attributes] == ["1.1.1.1"]
    assert client.sightings == ["8.8.8.8"]


async def test_publisher_resumes_publish_for_an_existing_event(
    store: object, settings_factory: object, incident_factory: object
) -> None:
    settings = settings_factory(  # type: ignore[operator]
        misp_enabled=True,
        misp_url="https://misp.test",
        misp_api_key="secret",
        misp_publish_grace=0,
        misp_publish_mode="auto",
    )
    known = {"8.8.8.8": (MispExistingAttribute(id=11, value="8.8.8.8"),)}
    event = MispEventBuilder(namespace="opencanary").build(
        MispWindow(start=START, end=START + timedelta(days=1), observations=())
    )
    existing = MispExistingEvent(
        id=42,
        uuid=event.uuid,
        attribute_values=frozenset({"8.8.8.8"}),
        tags=frozenset(event.tags),
        published=False,
    )
    client = FakeMisp(known=known, existing_event=existing)
    publisher = _publisher(store, settings, client)
    incident = incident_factory(  # type: ignore[operator]
        src_host="8.8.8.8",
        created=int(START.timestamp()),
        events_list=str(int(START.timestamp())),
        events_count=3,
    )

    await publisher.observe(incident)
    assert await publisher.run_once() == 1
    assert client.publish_calls == 1
    assert client.sightings == ["8.8.8.8"]


async def test_publisher_auto_publishes(
    store: object, settings_factory: object, incident_factory: object
) -> None:
    settings = settings_factory(  # type: ignore[operator]
        misp_enabled=True,
        misp_url="https://misp.test",
        misp_api_key="secret",
        misp_publish_grace=0,
        misp_publish_mode="auto",
    )
    incident = incident_factory(  # type: ignore[operator]
        src_host="8.8.8.8",
        created=int(START.timestamp()),
        events_list=str(int(START.timestamp())),
        events_count=3,
    )
    client = FakeMisp()
    publisher = _publisher(store, settings, client)

    await publisher.observe(incident)
    assert await publisher.run_once() == 1
    assert client.published is True
    assert client.publish_calls == 1


async def test_publisher_keeps_a_window_queued_when_warninglists_are_disabled(
    store: object, settings_factory: object, incident_factory: object
) -> None:
    settings = settings_factory(  # type: ignore[operator]
        misp_enabled=True,
        misp_url="https://misp.test",
        misp_api_key="secret",
        misp_publish_grace=0,
    )
    incident = incident_factory(  # type: ignore[operator]
        src_host="8.8.8.8",
        created=int(START.timestamp()),
        events_list=str(int(START.timestamp())),
    )
    publisher = _publisher(store, settings, FakeMisp(enabled=0))

    await publisher.observe(incident)
    assert await publisher.run_once() == 0
    assert await publisher._queue.pending_count() == 1


async def test_publisher_keeps_a_window_queued_when_a_tag_is_missing(
    store: object, settings_factory: object, incident_factory: object
) -> None:
    settings = settings_factory(  # type: ignore[operator]
        misp_enabled=True,
        misp_url="https://misp.test",
        misp_api_key="secret",
        misp_publish_grace=0,
    )
    incident = incident_factory(  # type: ignore[operator]
        src_host="8.8.8.8",
        created=int(START.timestamp()),
        events_list=str(int(START.timestamp())),
    )
    publisher = _publisher(store, settings, FakeMisp(tag=None))

    await publisher.observe(incident)
    assert await publisher.run_once() == 0
    assert await publisher._queue.pending_count() == 1
