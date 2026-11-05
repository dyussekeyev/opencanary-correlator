"""OpenCTI client: GraphQL query, cache, singleflight and failure modes."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import httpx
import pytest

from opencanary_correlator import metrics
from opencanary_correlator.enrichment.opencti import (
    ADD_INDICATOR_MUTATION,
    ADD_LABEL_MUTATION,
    INDICATOR_DESCRIPTION,
    INDICATOR_QUERY,
    PATCH_INDICATOR_MUTATION,
    OpenCTIClient,
    stix_datetime,
    stix_pattern,
)
from opencanary_correlator.storage import keys

ATTACKER = "74.22.3.178"
IPV6 = "2606:4700:4700::1111"
INDICATOR_NODE: dict[str, Any] = {
    "id": "indicator--1",
    "pattern": f"[ipv4-addr:value = '{ATTACKER}']",
    "confidence": 80,
    "created_at": "2026-10-26T10:00:00Z",
    "valid_from": "2026-10-26T10:00:00Z",
}


def body(node: dict[str, Any] | None = None) -> dict[str, Any]:
    """GraphQL envelope with zero or one indicator."""
    return {"data": {"indicators": {"edges": [] if node is None else [{"node": node}]}}}


def make_client(
    store: Any,
    answers: list[httpx.Response | Exception] | None = None,
    *,
    create_mode: str = "off",
    cache_ttl: float = 3600.0,
    miss_cache_ttl: float = 300.0,
    max_response_bytes: int = 1024 * 1024,
    lookup_timeout: float = 6.0,
) -> tuple[OpenCTIClient, list[httpx.Request]]:
    """Client whose transport replays `answers`, then answers "not found"."""
    seen: list[httpx.Request] = []
    queue = list(answers or [])

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        answer = queue.pop(0) if queue else httpx.Response(200, json=body())
        if isinstance(answer, Exception):
            raise answer
        return answer

    client = OpenCTIClient(
        url="https://opencti.example",
        token="test-token",
        store=store,
        create_mode=create_mode,  # type: ignore[arg-type]
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        cache_ttl=cache_ttl,
        miss_cache_ttl=miss_cache_ttl,
        max_response_bytes=max_response_bytes,
        lookup_timeout=lookup_timeout,
    )
    return client, seen


async def test_a_known_indicator_is_parsed_and_cached(store: Any) -> None:
    client, seen = make_client(store, [httpx.Response(200, json=body(INDICATOR_NODE))])
    try:
        indicator, status = await client.lookup(ATTACKER)
        cached, cached_status = await client.lookup(ATTACKER)
    finally:
        await client.aclose()

    assert status == "ok"
    assert indicator is not None
    assert indicator.id == "indicator--1"
    assert indicator.pattern == f"[ipv4-addr:value = '{ATTACKER}']"
    assert indicator.confidence == 80
    assert indicator.valid_from == "2026-10-26T10:00:00Z"
    # The second alert is answered from Redis: one query in total.
    assert cached == indicator
    assert cached_status == "ok"
    assert len(seen) == 1


async def test_no_indicator_is_a_negative_answer_not_a_failure(store: Any) -> None:
    client, seen = make_client(store, [httpx.Response(200, json=body())])
    try:
        assert await client.lookup(ATTACKER) == (None, "not_found")
        assert await client.lookup(ATTACKER) == (None, "not_found")
    finally:
        await client.aclose()

    assert len(seen) == 1
    ttl_ms = await store.client.pttl(keys.enrichment_cache_key("opencti", ATTACKER))
    assert 0 < ttl_ms <= 300_000


async def test_the_query_filters_on_the_exact_stix_pattern(store: Any) -> None:
    client, seen = make_client(store, [httpx.Response(200, json=body(INDICATOR_NODE))])
    try:
        await client.lookup(ATTACKER)
    finally:
        await client.aclose()

    request = seen[0]
    payload = json.loads(request.content)
    assert payload["query"] == INDICATOR_QUERY
    filters = payload["variables"]["filters"]["filters"]
    assert filters == [
        {
            "key": "pattern",
            "values": [f"[ipv4-addr:value = '{ATTACKER}']"],
            "operator": "eq",
        }
    ]
    assert str(request.url) == "https://opencti.example/graphql"
    assert request.headers["Authorization"] == "Bearer test-token"
    # The token is a header, never part of the URL a library might log.
    assert "test-token" not in str(request.url)


def test_the_pattern_follows_the_address_family() -> None:
    import ipaddress

    assert stix_pattern(ipaddress.ip_address(ATTACKER)) == f"[ipv4-addr:value = '{ATTACKER}']"
    assert stix_pattern(ipaddress.ip_address(IPV6)) == f"[ipv6-addr:value = '{IPV6}']"


async def test_equivalent_ipv6_forms_query_one_canonical_address(store: Any) -> None:
    client, seen = make_client(store, [httpx.Response(200, json=body())])
    try:
        await client.lookup("2606:4700:4700:0000:0000:0000:0000:1111")
        await client.lookup(IPV6)
    finally:
        await client.aclose()

    assert len(seen) == 1
    assert f"[ipv6-addr:value = '{IPV6}']" in seen[0].content.decode()


@pytest.mark.parametrize(
    ("answer", "expected"),
    [
        (httpx.Response(401), "unauthorized"),
        (httpx.Response(403), "unauthorized"),
        (httpx.Response(500), "unavailable"),
        (httpx.Response(404), "unavailable"),
        (httpx.ConnectError("offline"), "unavailable"),
        (httpx.ReadTimeout("slow"), "unavailable"),
    ],
)
async def test_transport_failures_never_raise(store: Any, answer: Any, expected: str) -> None:
    client, _seen = make_client(store, [answer, answer])
    try:
        first = await client.lookup(ATTACKER)
        second = await client.lookup(ATTACKER)
    finally:
        await client.aclose()

    assert first == (None, expected)
    # Failures are not cached as "not found": the next alert asks again.
    assert second == (None, expected)


async def test_a_graphql_error_is_not_mistaken_for_no_indicator(store: Any) -> None:
    error = httpx.Response(200, json={"errors": [{"message": "field does not exist"}]})
    client, seen = make_client(store, [error, error])
    try:
        assert await client.lookup(ATTACKER) == (None, "unavailable")
        assert await client.lookup(ATTACKER) == (None, "unavailable")
    finally:
        await client.aclose()

    assert len(seen) == 2
    assert await store.get_value(keys.enrichment_cache_key("opencti", ATTACKER)) is None


async def test_a_malformed_body_is_unavailable(store: Any) -> None:
    client, _seen = make_client(store, [httpx.Response(200, text="<html>nope</html>")])
    try:
        assert await client.lookup(ATTACKER) == (None, "unavailable")
    finally:
        await client.aclose()

    assert await store.get_value(keys.enrichment_cache_key("opencti", ATTACKER)) is None


@pytest.mark.parametrize(
    "payload",
    [
        {"data": []},
        {"data": {"indicators": []}},
        {"data": {"indicators": {"edges": [{"node": "nope"}]}}},
        [],
    ],
    ids=["data-not-object", "connection-not-object", "node-not-object", "envelope-not-object"],
)
async def test_malformed_shapes_are_unavailable(store: Any, payload: Any) -> None:
    client, _seen = make_client(store, [httpx.Response(200, json=payload)])
    try:
        assert await client.lookup(ATTACKER) == (None, "unavailable")
    finally:
        await client.aclose()


async def test_an_oversized_response_is_refused_before_parsing(store: Any) -> None:
    huge = httpx.Response(200, content=b'{"data": "padding"}')
    client, _seen = make_client(store, [huge], max_response_bytes=8)
    try:
        assert await client.lookup(ATTACKER) == (None, "unavailable")
    finally:
        await client.aclose()

    assert await store.get_value(keys.enrichment_cache_key("opencti", ATTACKER)) is None


async def test_odd_field_types_do_not_break_parsing(store: Any) -> None:
    node = {"id": 7, "pattern": None, "confidence": "unknown", "created_at": 1, "valid_from": None}
    client, _seen = make_client(store, [httpx.Response(200, json=body(node))])
    try:
        indicator, status = await client.lookup(ATTACKER)
    finally:
        await client.aclose()

    assert status == "ok"
    assert indicator is not None
    assert (indicator.id, indicator.pattern, indicator.confidence) == ("", "", None)
    assert indicator.created_at is None


@pytest.mark.parametrize("ip", ["10.0.0.1", "::1", "not-an-ip", ""])
async def test_direct_lookups_never_query_non_public_addresses(store: Any, ip: str) -> None:
    client, seen = make_client(store, [])
    try:
        assert await client.lookup(ip) == (None, "unavailable")
    finally:
        await client.aclose()

    assert seen == []


async def test_positive_cache_expires_after_the_configured_ttl(store: Any) -> None:
    client, seen = make_client(
        store,
        [
            httpx.Response(200, json=body(INDICATOR_NODE)),
            httpx.Response(200, json=body(INDICATOR_NODE)),
        ],
        cache_ttl=0.03,
    )
    try:
        first = await client.lookup(ATTACKER)
        assert await store.client.pttl(keys.enrichment_cache_key("opencti", ATTACKER)) > 0
        assert await client.lookup(ATTACKER) == first
        assert len(seen) == 1
        await asyncio.sleep(0.05)
        assert await client.lookup(ATTACKER) == first
    finally:
        await client.aclose()

    assert len(seen) == 2


async def test_a_zero_cache_ttl_disables_reuse(store: Any) -> None:
    answer = httpx.Response(200, json=body(INDICATOR_NODE))
    client, seen = make_client(store, [answer, answer], cache_ttl=0)
    try:
        first = await client.lookup(ATTACKER)
        assert await client.lookup(ATTACKER) == first
    finally:
        await client.aclose()

    assert len(seen) == 2
    assert await store.get_value(keys.enrichment_cache_key("opencti", ATTACKER)) is None


@pytest.mark.parametrize(
    "raw",
    [
        "not json",
        json.dumps({"found": True}),
        json.dumps({"found": True, "indicator": None}),
        json.dumps({"found": False, "indicator": INDICATOR_NODE}),
        json.dumps({"indicator": INDICATOR_NODE}),
    ],
    ids=["not-json", "hit-without-indicator", "contradictory-hit", "contradictory-miss", "no-flag"],
)
async def test_a_corrupt_cache_entry_is_a_miss(store: Any, raw: str) -> None:
    await store.set_with_ttl(keys.enrichment_cache_key("opencti", ATTACKER), raw, ttl=60)
    client, seen = make_client(store, [httpx.Response(200, json=body(INDICATOR_NODE))])
    try:
        indicator, status = await client.lookup(ATTACKER)
    finally:
        await client.aclose()

    assert status == "ok"
    assert indicator is not None and indicator.confidence == 80
    assert len(seen) == 1


async def test_two_clients_share_one_cached_answer(store: Any) -> None:
    hit = metrics.ENRICHMENT_CACHE.labels(provider="opencti", result="hit")
    before = hit._value.get()
    first, seen_first = make_client(store, [httpx.Response(200, json=body(INDICATOR_NODE))])
    second, seen_second = make_client(store, [])
    try:
        indicator = await first.lookup(ATTACKER)
        assert await second.lookup(ATTACKER) == indicator
    finally:
        await first.aclose()
        await second.aclose()

    assert len(seen_first) == 1
    assert seen_second == []
    assert hit._value.get() == before + 1


async def test_redis_failure_does_not_fall_back_to_http(store: Any, monkeypatch: Any) -> None:
    from unittest.mock import AsyncMock

    from redis.exceptions import ConnectionError as RedisConnectionError

    monkeypatch.setattr(store, "get_value", AsyncMock(side_effect=RedisConnectionError("offline")))
    client, seen = make_client(store, [])
    counter = metrics.ENRICHMENT_SKIPPED.labels(provider="opencti", reason="store_error")
    before = counter._value.get()
    try:
        with pytest.raises(RedisConnectionError):
            await client.lookup(ATTACKER)
    finally:
        await client.aclose()

    assert counter._value.get() == before + 1
    assert seen == []


async def test_a_timed_out_lookup_is_unavailable(store: Any) -> None:
    entered = asyncio.Event()

    async def handler(_request: httpx.Request) -> httpx.Response:
        entered.set()
        await asyncio.Event().wait()
        return httpx.Response(200, json=body())

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = OpenCTIClient(
            url="https://opencti.example",
            token="test-token",
            store=store,
            client=http,
            lookup_timeout=0.05,
        )
        assert await asyncio.wait_for(client.lookup(ATTACKER), 1) == (None, "unavailable")
    assert entered.is_set()


async def test_concurrent_alerts_share_one_query(store: Any) -> None:
    entered = asyncio.Event()
    release = asyncio.Event()
    seen: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        entered.set()
        await release.wait()
        return httpx.Response(200, json=body(INDICATOR_NODE))

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = OpenCTIClient(
            url="https://opencti.example", token="test-token", store=store, client=http
        )
        tasks = [asyncio.create_task(client.lookup(ATTACKER))]
        try:
            await asyncio.wait_for(entered.wait(), 1)
            tasks.extend(asyncio.create_task(client.lookup(ATTACKER)) for _ in range(4))
            await asyncio.sleep(0.05)
            release.set()
            results = await asyncio.wait_for(asyncio.gather(*tasks), 2)
        finally:
            release.set()
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    assert all(result == results[0] for result in results)
    assert results[0][1] == "ok"
    assert len(seen) == 1


async def test_audit_keeps_the_token_and_the_address_out(
    store: Any, audit: Any, audit_stream: Any
) -> None:
    client, _seen = make_client(store, [httpx.Response(500), httpx.Response(401)])
    client._audit = audit
    try:
        await client.lookup(ATTACKER)
        await client.lookup("8.8.8.8")
    finally:
        await client.aclose()

    records = [json.loads(line) for line in audit_stream.getvalue().splitlines()]
    assert [record["action"] for record in records] == ["opencti_failed", "opencti_failed"]
    for record in records:
        assert set(record) == {"timestamp", "component", "action", "status", "details"}
    text = audit_stream.getvalue()
    assert ATTACKER not in text
    assert "8.8.8.8" not in text
    assert "test-token" not in text


async def test_the_client_closes_the_pool_it_created_itself(store: Any) -> None:
    client = OpenCTIClient(url="https://opencti.example", token="test-token", store=store)

    await client.aclose()

    assert client._client.is_closed


async def test_a_trailing_slash_does_not_double_the_graphql_path(store: Any) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=body())

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = OpenCTIClient(
            url="https://opencti.example/", token="test-token", store=store, client=http
        )
        await client.lookup(ATTACKER)

    assert str(seen[0].url) == "https://opencti.example/graphql"


# --- Create and update ------------------------------------------------------

VALID_FROM = datetime(2026, 11, 5, 12, 0, tzinfo=UTC)
VALID_FROM_TEXT = "2026-11-05T12:00:00.000Z"


def created(node: dict[str, Any] | None = INDICATOR_NODE) -> dict[str, Any]:
    return {"data": {"indicatorAdd": node}}


def patched(node: dict[str, Any] | None = INDICATOR_NODE) -> dict[str, Any]:
    return {"data": {"indicatorFieldPatch": node}}


def labels_body(*nodes: tuple[str, str]) -> dict[str, Any]:
    """`labels` connection with one node per (id, value) pair."""
    return {
        "data": {
            "labels": {
                "edges": [
                    {"node": {"id": identifier, "value": value}} for identifier, value in nodes
                ]
            }
        }
    }


def label_added(identifier: str, value: str) -> dict[str, Any]:
    return {"data": {"labelAdd": {"id": identifier, "value": value}}}


async def test_missing_creates_a_stix_indicator_when_nothing_was_found(store: Any) -> None:
    client, seen = make_client(
        store,
        [
            httpx.Response(200, json=body()),
            httpx.Response(200, json=labels_body(("label--1", "opencanary"))),
            httpx.Response(200, json=labels_body(("label--2", "honeypot"))),
            httpx.Response(200, json=created()),
        ],
        create_mode="missing",
    )
    try:
        result = await client.create_or_update(
            ATTACKER,
            confidence=80,
            labels=("opencanary", "honeypot"),
            valid_from=VALID_FROM,
        )
    finally:
        await client.aclose()

    assert result.outcome == "created"
    assert result.status == "ok"
    assert result.indicator is not None and result.indicator.id == "indicator--1"
    assert len(seen) == 4
    payload = json.loads(seen[3].content)
    assert payload["query"] == ADD_INDICATOR_MUTATION
    assert payload["variables"]["input"] == {
        "name": ATTACKER,
        "pattern": f"[ipv4-addr:value = '{ATTACKER}']",
        "pattern_type": "stix",
        "x_opencti_main_observable_type": "IPv4-Addr",
        "valid_from": VALID_FROM_TEXT,
        "confidence": 80,
        "objectLabel": ["label--1", "label--2"],
        "description": INDICATOR_DESCRIPTION,
    }
    # The description must never carry honeypot data or a node identifier.
    assert "canary" not in INDICATOR_DESCRIPTION


async def test_missing_leaves_an_existing_indicator_alone(store: Any) -> None:
    client, seen = make_client(
        store, [httpx.Response(200, json=body(INDICATOR_NODE))], create_mode="missing"
    )
    try:
        result = await client.create_or_update(ATTACKER, confidence=80, valid_from=VALID_FROM)
    finally:
        await client.aclose()

    assert result.outcome == "existing"
    assert result.indicator is not None and result.indicator.confidence == 80
    assert len(seen) == 1


async def test_always_creates_when_the_indicator_is_missing(store: Any) -> None:
    client, seen = make_client(
        store,
        [httpx.Response(200, json=body()), httpx.Response(200, json=created())],
        create_mode="always",
    )
    try:
        result = await client.create_or_update(ATTACKER, confidence=50, valid_from=VALID_FROM)
    finally:
        await client.aclose()

    assert result.outcome == "created"
    assert json.loads(seen[1].content)["query"] == ADD_INDICATOR_MUTATION


async def test_always_updates_an_existing_indicator(store: Any) -> None:
    client, seen = make_client(
        store,
        [
            httpx.Response(200, json=body(INDICATOR_NODE)),
            httpx.Response(200, json=labels_body(("label--1", "opencanary"))),
            httpx.Response(200, json=patched()),
        ],
        create_mode="always",
    )
    try:
        result = await client.create_or_update(
            ATTACKER, confidence=90, labels=("opencanary",), valid_from=VALID_FROM
        )
    finally:
        await client.aclose()

    assert result.outcome == "updated"
    assert result.indicator is not None and result.indicator.id == "indicator--1"
    payload = json.loads(seen[2].content)
    assert payload["query"] == PATCH_INDICATOR_MUTATION
    assert payload["variables"] == {
        "id": "indicator--1",
        "input": [
            {"key": "confidence", "value": ["90"]},
            {"key": "valid_from", "value": [VALID_FROM_TEXT]},
            {"key": "objectLabel", "value": ["label--1"]},
        ],
    }


@pytest.mark.parametrize(
    ("answer", "status"),
    [(httpx.Response(401), "unauthorized"), (httpx.Response(500), "unavailable")],
)
async def test_a_failed_lookup_never_writes(store: Any, answer: Any, status: str) -> None:
    client, seen = make_client(store, [answer], create_mode="always")
    try:
        result = await client.create_or_update(ATTACKER, confidence=80, valid_from=VALID_FROM)
    finally:
        await client.aclose()

    assert result.outcome == "skipped"
    assert result.status == status
    assert result.reason == f"lookup_{status}"
    # Only the lookup reached the network; no mutation was attempted.
    assert len(seen) == 1


async def test_a_graphql_error_on_the_lookup_never_writes(store: Any) -> None:
    error = httpx.Response(200, json={"errors": [{"message": "bad filter"}]})
    client, seen = make_client(store, [error], create_mode="always")
    try:
        result = await client.create_or_update(ATTACKER, confidence=80, valid_from=VALID_FROM)
    finally:
        await client.aclose()

    assert result.outcome == "skipped"
    assert result.status == "unavailable"
    assert len(seen) == 1


async def test_off_never_touches_the_network(store: Any) -> None:
    client, seen = make_client(store, [])
    try:
        result = await client.create_or_update(ATTACKER, confidence=80)
    finally:
        await client.aclose()

    assert (result.outcome, result.status, result.reason) == (
        "skipped",
        "disabled",
        "create_disabled",
    )
    assert seen == []


async def test_a_failed_create_is_reported_not_raised(
    store: Any, audit: Any, audit_stream: Any
) -> None:
    client, _seen = make_client(
        store,
        [httpx.Response(200, json=body()), httpx.Response(500)],
        create_mode="missing",
    )
    client._audit = audit
    try:
        result = await client.create_or_update(ATTACKER, confidence=80, valid_from=VALID_FROM)
    finally:
        await client.aclose()

    assert result.outcome == "failed"
    assert result.status == "unavailable"
    assert result.reason == "http_error"
    # The cached answer is still the negative lookup: no phantom indicator.
    raw = await store.get_value(keys.enrichment_cache_key("opencti", ATTACKER))
    assert json.loads(raw or "null") == {"found": False, "indicator": None}
    records = [json.loads(line) for line in audit_stream.getvalue().splitlines()]
    failed = [record for record in records if record["action"] == "opencti_failed"]
    assert failed[-1]["details"] == {"reason": "http_error", "operation": "create"}
    text = audit_stream.getvalue()
    assert ATTACKER not in text
    assert "test-token" not in text


async def test_a_rejected_mutation_is_unauthorized(store: Any) -> None:
    client, _seen = make_client(
        store,
        [httpx.Response(200, json=body()), httpx.Response(401)],
        create_mode="missing",
    )
    try:
        result = await client.create_or_update(ATTACKER, confidence=80, valid_from=VALID_FROM)
    finally:
        await client.aclose()

    assert (result.outcome, result.status) == ("failed", "unauthorized")


async def test_a_mutation_without_a_node_still_reports_the_indicator(store: Any) -> None:
    client, _seen = make_client(
        store,
        [
            httpx.Response(200, json=body()),
            httpx.Response(200, json=labels_body(("label--1", "opencanary"))),
            httpx.Response(200, json=created(None)),
        ],
        create_mode="missing",
    )
    try:
        result = await client.create_or_update(
            ATTACKER, confidence=70, labels=("opencanary",), valid_from=VALID_FROM
        )
    finally:
        await client.aclose()

    assert result.outcome == "created"
    assert result.indicator is not None
    assert result.indicator.pattern == f"[ipv4-addr:value = '{ATTACKER}']"
    assert result.indicator.confidence == 70
    assert result.indicator.valid_from == VALID_FROM_TEXT
    assert result.indicator.labels == ("opencanary",)


async def test_a_created_indicator_answers_the_next_lookup_from_the_cache(store: Any) -> None:
    client, seen = make_client(
        store,
        [httpx.Response(200, json=body()), httpx.Response(200, json=created())],
        create_mode="missing",
    )
    try:
        assert (await client.create_or_update(ATTACKER, confidence=80)).outcome == "created"
        indicator, status = await client.lookup(ATTACKER)
        again = await client.create_or_update(ATTACKER, confidence=80)
    finally:
        await client.aclose()

    assert status == "ok"
    assert indicator is not None and indicator.id == "indicator--1"
    assert again.outcome == "existing"
    assert len(seen) == 2


async def test_an_existing_indicator_without_an_id_is_never_patched(store: Any) -> None:
    entry = json.dumps({"found": True, "indicator": {"pattern": "x", "confidence": 10}})
    await store.set_with_ttl(keys.enrichment_cache_key("opencti", ATTACKER), entry, ttl=60)
    client, seen = make_client(store, [], create_mode="always")
    try:
        result = await client.create_or_update(ATTACKER, confidence=80)
    finally:
        await client.aclose()

    assert (result.outcome, result.reason) == ("skipped", "missing_indicator_id")
    assert seen == []


async def test_the_old_indicator_is_reported_when_the_patch_fails(store: Any) -> None:
    client, _seen = make_client(
        store,
        [httpx.Response(200, json=body(INDICATOR_NODE)), httpx.Response(400)],
        create_mode="always",
    )
    try:
        result = await client.create_or_update(ATTACKER, confidence=90, valid_from=VALID_FROM)
    finally:
        await client.aclose()

    assert result.outcome == "failed"
    assert result.status == "unavailable"
    assert result.indicator is not None and result.indicator.id == "indicator--1"


@pytest.mark.parametrize("ip", ["10.0.0.1", "::1", "not-an-ip"])
async def test_non_public_addresses_are_never_created(store: Any, ip: str) -> None:
    client, seen = make_client(store, [], create_mode="always")
    try:
        result = await client.create_or_update(ip, confidence=80)
    finally:
        await client.aclose()

    assert (result.outcome, result.reason) == ("skipped", "not_public")
    assert seen == []


async def test_ipv6_creation_uses_the_ipv6_observable_type(store: Any) -> None:
    client, seen = make_client(
        store,
        [httpx.Response(200, json=body()), httpx.Response(200, json=created())],
        create_mode="missing",
    )
    try:
        await client.create_or_update(IPV6, confidence=80, valid_from=VALID_FROM)
    finally:
        await client.aclose()

    fields = json.loads(seen[1].content)["variables"]["input"]
    assert fields["pattern"] == f"[ipv6-addr:value = '{IPV6}']"
    assert fields["x_opencti_main_observable_type"] == "IPv6-Addr"


async def test_empty_labels_are_not_sent(store: Any) -> None:
    """An empty list would clear labels an operator set by hand."""
    client, seen = make_client(
        store,
        [httpx.Response(200, json=body()), httpx.Response(200, json=created())],
        create_mode="missing",
    )
    try:
        await client.create_or_update(ATTACKER, confidence=80, labels=())
    finally:
        await client.aclose()

    assert "objectLabel" not in json.loads(seen[1].content)["variables"]["input"]


async def test_a_missing_label_is_created_before_the_indicator(store: Any) -> None:
    client, seen = make_client(
        store,
        [
            httpx.Response(200, json=body()),
            httpx.Response(200, json=labels_body()),
            httpx.Response(200, json=label_added("label--9", "opencanary")),
            httpx.Response(200, json=created()),
        ],
        create_mode="missing",
    )
    try:
        result = await client.create_or_update(ATTACKER, confidence=80, labels=("opencanary",))
    finally:
        await client.aclose()

    assert result.outcome == "created"
    assert json.loads(seen[2].content)["query"] == ADD_LABEL_MUTATION
    assert json.loads(seen[2].content)["variables"] == {"input": {"value": "opencanary"}}
    assert json.loads(seen[3].content)["variables"]["input"]["objectLabel"] == ["label--9"]


async def test_an_unresolvable_label_does_not_block_the_indicator(store: Any) -> None:
    """The indicator is the product; a label failure is metadata only."""
    client, seen = make_client(
        store,
        [
            httpx.Response(200, json=body()),
            httpx.Response(500),
            httpx.Response(500),
            httpx.Response(200, json=created()),
        ],
        create_mode="missing",
    )
    try:
        result = await client.create_or_update(ATTACKER, confidence=80, labels=("opencanary",))
    finally:
        await client.aclose()

    assert result.outcome == "created"
    fields = json.loads(seen[3].content)["variables"]["input"]
    assert "objectLabel" not in fields


def test_stix_datetime_is_utc_with_milliseconds() -> None:
    assert stix_datetime(VALID_FROM) == VALID_FROM_TEXT
    # A naive timestamp is read as UTC, matching how incidents are stored.
    assert stix_datetime(datetime(2026, 11, 5, 12, 0)) == VALID_FROM_TEXT
    offset = datetime(2026, 11, 5, 14, 0, tzinfo=timezone(timedelta(hours=2)))
    assert stix_datetime(offset) == VALID_FROM_TEXT


@pytest.mark.parametrize("confidence", [-1, 101])
async def test_confidence_outside_the_stix_range_is_rejected(store: Any, confidence: int) -> None:
    client, seen = make_client(store, [], create_mode="always")
    try:
        with pytest.raises(ValueError, match="confidence"):
            await client.create_or_update(ATTACKER, confidence=confidence)
    finally:
        await client.aclose()

    assert seen == []


def test_an_unknown_create_mode_is_rejected(store: Any) -> None:
    with pytest.raises(ValueError, match="create_mode"):
        OpenCTIClient(
            url="https://opencti.example",
            token="test-token",
            store=store,
            create_mode="sometimes",  # type: ignore[arg-type]
        )
