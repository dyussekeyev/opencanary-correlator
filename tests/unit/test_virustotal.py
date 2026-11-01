"""VirusTotal client: parsing, cache, quota windows and failure modes."""

from __future__ import annotations

import asyncio
import json
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest

from opencanary_correlator import metrics
from opencanary_correlator.enrichment.virustotal import QuotaLimits, VirusTotalClient
from opencanary_correlator.storage import keys

ATTACKER = "74.22.3.178"
PAYLOAD: dict[str, Any] = {
    "data": {
        "attributes": {
            "last_analysis_stats": {
                "malicious": 12,
                "suspicious": 2,
                "harmless": 60,
                "undetected": 20,
                "timeout": 0,
            },
            "reputation": -34,
            "last_analysis_date": 1793000000,
        }
    }
}


def make_client(
    store: Any,
    answers: list[httpx.Response | Exception],
    *,
    limits: QuotaLimits | None = None,
    clock: Any = None,
) -> tuple[VirusTotalClient, list[httpx.Request]]:
    """Client whose transport replays `answers` in order."""
    seen: list[httpx.Request] = []
    queue = list(answers)

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        answer = queue.pop(0) if queue else httpx.Response(200, json=PAYLOAD)
        if isinstance(answer, Exception):
            raise answer
        return answer

    client = VirusTotalClient(
        api_key="test-key",
        store=store,
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        limits=limits,
        clock=clock or (lambda: 1_793_200_000.0),
    )
    return client, seen


@pytest.mark.parametrize(
    "body,cache_result", [(PAYLOAD, "hit"), ({"data": {"attributes": {}}}, "negative_hit")]
)
async def test_metrics_count_initial_cache_lookup_and_actual_http(
    store: Any, body: Any, cache_result: str
) -> None:
    miss = metrics.ENRICHMENT_CACHE.labels(provider="virustotal", result="miss")
    hit = metrics.ENRICHMENT_CACHE.labels(provider="virustotal", result=cache_result)
    requests = metrics.ENRICHMENT_REQUESTS.labels(provider="virustotal", outcome="ok")
    before = (miss._value.get(), hit._value.get(), requests._value.get())
    client, seen = make_client(store, [httpx.Response(200, json=body)])
    await client.report(ATTACKER)
    await client.report(ATTACKER)
    assert (miss._value.get(), hit._value.get(), requests._value.get()) == tuple(
        x + 1 for x in before
    )
    assert len(seen) == 1


async def test_cooldown_audit_has_no_identifiers_or_credentials(
    store: Any, audit: Any, audit_stream: Any
) -> None:
    client, _ = make_client(store, [httpx.Response(401)])
    client._audit = audit
    skipped = metrics.ENRICHMENT_SKIPPED.labels(provider="virustotal", reason="cooldown_auth")
    before = skipped._value.get()
    await client.report(ATTACKER)
    await client.report("8.8.8.8")
    await client._pause("auth", "unauthorized", 1)
    assert skipped._value.get() == before + 1
    records = [json.loads(line) for line in audit_stream.getvalue().splitlines()]
    assert [r["action"] for r in records].count("enrichment_cooldown_changed") == 1
    assert any(
        r["action"] == "enrichment_request_skipped" and r["details"]["reason"] == "cooldown_auth"
        for r in records
    )
    for record in records:
        assert set(record) == {"timestamp", "component", "action", "status", "details"}
    for forbidden in (ATTACKER, "8.8.8.8", "test-key", client._cooldown_key("auth")):
        assert forbidden not in audit_stream.getvalue()


@pytest.mark.parametrize(
    "failure,outcome",
    [
        (httpx.ReadTimeout("timeout"), "timeout"),
        (httpx.ConnectError("offline"), "network_error"),
        (httpx.Response(503), "http_error"),
        (httpx.Response(429), "quota"),
        (httpx.Response(401), "unauthorized"),
    ],
)
async def test_http_failure_metrics_are_not_counted_again_for_cooldown(
    store: Any, failure: Any, outcome: str
) -> None:
    counter = metrics.ENRICHMENT_REQUESTS.labels(provider="virustotal", outcome=outcome)
    before = counter._value.get()
    client, seen = make_client(store, [failure])
    await client.report(ATTACKER)
    await client.report("8.8.8.8")
    assert counter._value.get() == before + 1
    assert len(seen) == 1


async def test_quota_skip_counts_no_http(store: Any) -> None:
    counter = metrics.ENRICHMENT_SKIPPED.labels(provider="virustotal", reason="quota")
    before = counter._value.get()
    client, seen = make_client(store, [], limits=QuotaLimits(0, 0, 0))
    assert (await client.report(ATTACKER))[1] == "quota"
    assert counter._value.get() == before + 1
    assert seen == []


async def test_a_report_is_parsed_and_cached(store: Any) -> None:
    client, seen = make_client(store, [httpx.Response(200, json=PAYLOAD)])
    try:
        report, status = await client.report(ATTACKER)
        second, second_status = await client.report(ATTACKER)
    finally:
        await client.aclose()

    assert status == "ok"
    assert report is not None
    verdict = (report.malicious, report.suspicious, report.harmless, report.undetected)
    assert verdict == (12, 2, 60, 20)
    assert report.detections == 14
    assert report.total == 94
    assert report.reputation == -34
    assert report.checked == "2026-10-26"
    # The second lookup is served from Redis: one request in total.
    assert len(seen) == 1
    assert second == report
    assert second_status == "ok"


async def test_the_key_travels_in_a_header_not_the_url(store: Any) -> None:
    client, seen = make_client(store, [httpx.Response(200, json=PAYLOAD)])
    try:
        await client.report(ATTACKER)
    finally:
        await client.aclose()

    assert seen[0].headers["x-apikey"] == "test-key"
    assert "test-key" not in str(seen[0].url)
    assert str(seen[0].url).endswith(ATTACKER)


async def test_the_quota_is_enforced_per_minute(store: Any) -> None:
    limits = QuotaLimits(per_minute=2, per_day=100, per_month=1000)
    addresses = ["74.22.3.1", "74.22.3.2", "74.22.3.3"]
    client, seen = make_client(store, [], limits=limits)
    try:
        results = [await client.report(ip) for ip in addresses]
    finally:
        await client.aclose()

    assert [status for _report, status in results] == ["ok", "ok", "quota"]
    assert len(seen) == 2


async def test_the_quota_is_shared_through_redis(store: Any) -> None:
    """Two replicas with the same limits must not each get a full minute."""
    limits = QuotaLimits(per_minute=1, per_day=100, per_month=1000)
    first, seen_first = make_client(store, [], limits=limits)
    second, seen_second = make_client(store, [], limits=limits)
    try:
        assert (await first.report("74.22.3.1"))[1] == "ok"
        assert (await second.report("74.22.3.2"))[1] == "quota"
    finally:
        await first.aclose()
        await second.aclose()

    assert len(seen_first) == 1
    assert seen_second == []


async def test_a_new_minute_starts_with_a_fresh_window(store: Any) -> None:
    now = 1_793_200_000.0
    limits = QuotaLimits(per_minute=1, per_day=100, per_month=1000)
    client, _seen = make_client(store, [], limits=limits, clock=lambda: now)
    try:
        assert (await client.report("74.22.3.1"))[1] == "ok"
        assert (await client.report("74.22.3.2"))[1] == "quota"
        client._clock = lambda: now + 61
        assert (await client.report("74.22.3.3"))[1] == "ok"
    finally:
        await client.aclose()


@pytest.mark.parametrize(
    ("answer", "expected"),
    [
        (httpx.Response(429), "quota"),
        # A refused key is its own outcome: nothing is known about the attacker,
        # but "your key is wrong" is not the same problem as "the API is down".
        (httpx.Response(401), "unauthorized"),
        (httpx.Response(403), "unauthorized"),
        (httpx.Response(500), "unavailable"),
        (httpx.ConnectError("boom"), "unavailable"),
        (httpx.Response(200, json={"data": {"attributes": {}}}), "ok"),
    ],
)
async def test_failures_never_raise(store: Any, answer: Any, expected: str) -> None:
    client, _seen = make_client(store, [answer])
    try:
        report, status = await client.report(ATTACKER)
    finally:
        await client.aclose()

    assert status == expected
    assert report is None


async def test_the_spent_window_is_named(store: Any) -> None:
    """ "Wait a minute" and "the daily budget is gone" are different answers."""
    now = 1_793_200_000.0
    limits = QuotaLimits(per_minute=1, per_day=2, per_month=10)
    client, _seen = make_client(store, [], limits=limits, clock=lambda: now)
    try:
        assert (await client.report("74.22.4.1"))[1] == "ok"
        assert (await client.report("74.22.4.2"))[1] == "quota"
        assert await client.exhausted_window() == "minute"
        client._clock = lambda: now + 61
        assert (await client.report("74.22.4.3"))[1] == "ok"
        # A fresh minute, but the day's two slots are gone.
        client._clock = lambda: now + 122
        assert (await client.report("74.22.4.4"))[1] == "quota"
        assert await client.exhausted_window() == "day"
    finally:
        await client.aclose()


async def test_a_quota_refusal_still_shows_a_status(store: Any) -> None:
    """The reported choice: an exhausted window is visible, not silent."""
    limits = QuotaLimits(per_minute=0, per_day=0, per_month=0)
    client, seen = make_client(store, [], limits=limits)
    try:
        report, status = await client.report(ATTACKER)
    finally:
        await client.aclose()

    assert (report, status) == (None, "quota")
    assert seen == []


async def test_a_cached_result_survives_a_spent_quota(store: Any) -> None:
    cached = {"malicious": 1, "suspicious": 0, "harmless": 0, "undetected": 92, "reputation": 0}
    await store.set_with_ttl(keys.enrichment_cache_key("vt", ATTACKER), json.dumps(cached), ttl=60)
    limits = QuotaLimits(per_minute=0, per_day=0, per_month=0)
    client, seen = make_client(store, [], limits=limits)
    try:
        report, status = await client.report(ATTACKER)
    finally:
        await client.aclose()

    assert status == "ok"
    assert report is not None and report.malicious == 1
    assert seen == []


async def test_a_corrupt_cache_entry_is_treated_as_a_miss(store: Any) -> None:
    await store.set_with_ttl(keys.enrichment_cache_key("vt", ATTACKER), "not json", ttl=60)
    client, seen = make_client(store, [httpx.Response(200, json=PAYLOAD)])
    try:
        report, status = await client.report(ATTACKER)
    finally:
        await client.aclose()

    assert status == "ok" and report is not None
    assert len(seen) == 1


async def test_a_malformed_response_body_is_unavailable(store: Any) -> None:
    client, _seen = make_client(store, [httpx.Response(200, text="<html>nope</html>")])
    try:
        assert (await client.report(ATTACKER))[1] == "unavailable"
    finally:
        await client.aclose()


async def test_odd_field_types_do_not_break_parsing(store: Any) -> None:
    body = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": None, "suspicious": "3", "harmless": "x"},
                "reputation": "unknown",
                "last_analysis_date": "not-a-date",
            }
        }
    }
    client, _seen = make_client(store, [httpx.Response(200, json=body)])
    try:
        report, status = await client.report(ATTACKER)
    finally:
        await client.aclose()

    assert status == "ok"
    assert report is not None
    assert (report.malicious, report.suspicious, report.harmless) == (0, 3, 0)
    assert report.reputation is None
    assert report.checked is None


async def test_an_empty_verdict_is_cached_briefly(store: Any) -> None:
    client, seen = make_client(store, [httpx.Response(200, json={"data": {"attributes": {}}})])
    try:
        assert (await client.report(ATTACKER))[1] == "ok"
        assert (await client.report(ATTACKER))[1] == "ok"
    finally:
        await client.aclose()

    assert len(seen) == 1
    ttl_ms = await store.client.pttl(keys.enrichment_cache_key("vt", ATTACKER))
    assert 0 < ttl_ms <= 3_600_000


async def test_a_cache_entry_that_fails_validation_is_a_miss(store: Any) -> None:
    """An entry written by an older build must be re-queried, not trusted."""
    await store.set_with_ttl(
        keys.enrichment_cache_key("vt", ATTACKER), json.dumps({"malicious": "many"}), ttl=60
    )
    client, seen = make_client(store, [httpx.Response(200, json=PAYLOAD)])
    try:
        report, status = await client.report(ATTACKER)
    finally:
        await client.aclose()

    assert status == "ok"
    assert report is not None and report.malicious == 12
    assert len(seen) == 1


@pytest.mark.parametrize(
    "body",
    [
        {"data": []},
        {"data": {"attributes": {"last_analysis_stats": "nope"}}},
        {"data": {}},
        [{"data": {}}],
    ],
    ids=["shapes-not-dicts", "stats-not-dict", "attributes-missing", "payload-not-an-object"],
)
async def test_malformed_shapes_are_unavailable_and_pause_requests(
    store: Any, body: dict[str, Any]
) -> None:
    """Malformed envelopes are failures, not successful empty reputations."""
    client, seen = make_client(store, [httpx.Response(200, json=body)])
    try:
        first = await client.report(ATTACKER)
        second = await client.report(ATTACKER)
    finally:
        await client.aclose()

    assert first[1] == "unavailable"
    assert second[1] == "unavailable"
    assert second[0] == first[0]
    assert len(seen) == 1


@pytest.mark.parametrize(
    "code,status",
    [(401, "unauthorized"), (403, "unauthorized"), (429, "quota"), (503, "unavailable")],
)
async def test_provider_cooldown_is_shared_and_cache_wins(
    store: Any, code: int, status: str
) -> None:
    first, seen = make_client(store, [httpx.Response(code)])
    second, other_seen = make_client(store, [])
    assert (await first.report(ATTACKER))[1] == status
    assert (await second.report("8.8.8.8"))[1] == status
    assert len(seen) == 1 and other_seen == []
    await store.set_with_ttl(
        keys.enrichment_cache_key("vt", "8.8.8.8"), json.dumps({"malicious": 1}), ttl=60
    )
    assert (await second.report("8.8.8.8"))[1] == "ok"


async def test_not_found_is_negative_cached(store: Any) -> None:
    client, seen = make_client(
        store, [httpx.Response(404, json={"error": {"code": "NotFoundError"}})]
    )
    assert await client.report(ATTACKER) == (None, "ok")
    assert await client.report(ATTACKER) == (None, "ok")
    assert len(seen) == 1


async def test_auth_cooldown_does_not_survive_key_rotation(store: Any) -> None:
    client, _ = make_client(store, [httpx.Response(401)])
    assert (await client.report(ATTACKER))[1] == "unauthorized"
    second, seen = make_client(store, [])
    second._api_key = "rotated-test-key"
    assert (await second.report(ATTACKER))[1] == "ok"
    assert len(seen) == 1


@pytest.mark.parametrize(
    "header,expected",
    [
        (None, 60),
        ("garbage", 60),
        ("120", 120),
        ("999999999999", 3600),
        ("0", 1),
        ("-2", 60),
        ("Wed, 21 Oct 2015 07:28:00 GMT", 1),
    ],
)
async def test_retry_after_is_bounded(store: Any, header: str | None, expected: float) -> None:
    client, _ = make_client(store, [])
    assert client._retry_after(header) == expected
    from email.utils import formatdate

    assert client._retry_after(formatdate(client._clock() + 120, usegmt=True)) == 120


async def test_cooldown_expiry_and_atomic_extension(store: Any) -> None:
    client, seen = make_client(store, [httpx.Response(503)])
    client._error_cooldown = 0.03
    assert (await client.report(ATTACKER))[1] == "unavailable"
    await asyncio.sleep(0.05)
    assert (await client.report(ATTACKER))[1] == "ok"
    assert len(seen) == 2
    await asyncio.gather(client._pause("rate", "quota", 100), client._pause("rate", "quota", 1))
    assert await store.client.pttl(client._cooldown_key("rate")) > 99000


async def test_timeout_sets_shared_pause(store: Any) -> None:
    counter = metrics.ENRICHMENT_REQUESTS.labels(provider="virustotal", outcome="timeout")
    before = counter._value.get()

    async def handler(request: httpx.Request) -> httpx.Response:
        await asyncio.Event().wait()
        return httpx.Response(200)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = VirusTotalClient(api_key="test-key", store=store, client=http, lookup_timeout=0.1)
        assert (await client.report(ATTACKER))[1] == "unavailable"
    assert counter._value.get() == before + 1
    other, seen = make_client(store, [])
    assert (await other.report("8.8.8.8"))[1] == "unavailable"
    assert seen == []


async def test_bad_marker_cannot_disable_lookups_forever(store: Any) -> None:
    client, seen = make_client(store, [])
    await store.set_with_ttl(client._cooldown_key("auth"), "not json", ttl=60)
    assert (await client.report(ATTACKER))[1] == "ok"
    assert len(seen) == 1


async def test_the_client_closes_the_http_pool_it_created_itself(store: Any) -> None:
    """Without a caller-supplied client, `aclose()` is what frees the pool.

    There is no public handle on the pool, so the assertion inspects the
    instance's own client: a leak here shows up as an unclosed transport at
    shutdown.
    """
    client = VirusTotalClient(api_key="test-key", store=store)

    await client.aclose()

    assert client._client.is_closed


@pytest.mark.parametrize("body", [PAYLOAD, {"data": {"attributes": {}}}], ids=["report", "no-data"])
async def test_concurrent_replicas_share_one_request(store: Any, body: Any) -> None:
    entered = asyncio.Event()
    release = asyncio.Event()
    seen: list[httpx.Request] = []
    miss = metrics.ENRICHMENT_CACHE.labels(provider="virustotal", result="miss")
    request_counter = metrics.ENRICHMENT_REQUESTS.labels(provider="virustotal", outcome="ok")
    before_miss, before_requests = miss._value.get(), request_counter._value.get()

    async def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        entered.set()
        await release.wait()
        return httpx.Response(200, json=body)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        clients = [VirusTotalClient(api_key="test-key", store=store, client=http) for _ in range(2)]
        tasks = [asyncio.create_task(clients[0].report(ATTACKER))]
        try:
            await asyncio.wait_for(entered.wait(), 1)
            tasks.extend(asyncio.create_task(clients[i % 2].report(ATTACKER)) for i in range(6))
            await asyncio.sleep(0.05)
            assert len(seen) == 1
            release.set()
            results = await asyncio.wait_for(asyncio.gather(*tasks), 2)
            assert all(result == results[0] for result in results)
            assert results[0][1] == "ok"
            assert len(seen) == 1
            assert miss._value.get() == before_miss + 7
            assert request_counter._value.get() == before_requests + 1
            for key, _limit, _ttl, _name in clients[0]._quota_windows():
                assert await store.get_value(key) == "1"
        finally:
            release.set()
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)


async def test_equivalent_ipv6_addresses_share_the_cache(store: Any) -> None:
    client, seen = make_client(store, [])
    first = await client.report("2606:4700:4700:0000:0000:0000:0000:1111")
    assert await client.report("2606:4700:4700::1111") == first
    assert len(seen) == 1
    assert str(seen[0].url).endswith("2606:4700:4700::1111")


@pytest.mark.parametrize("ip", ["10.0.0.1", "::1", "not-an-ip"])
async def test_direct_client_never_queries_non_public_addresses(store: Any, ip: str) -> None:
    client, seen = make_client(store, [])
    assert await client.report(ip) == (None, "unavailable")
    assert seen == []


async def test_waiter_deadline_does_not_bypass_the_lock(store: Any) -> None:
    client, seen = make_client(store, [])
    client._lookup_timeout = 0.03
    skipped = metrics.ENRICHMENT_SKIPPED.labels(
        provider="virustotal", reason="singleflight_timeout"
    )
    before = skipped._value.get()
    async with store.lock(keys.enrichment_lock_key("vt", ATTACKER), ttl_ms=1000):
        assert await asyncio.wait_for(client.report(ATTACKER), 0.5) == (None, "unavailable")
    assert seen == []
    assert skipped._value.get() == before + 1
    assert await client.report(ATTACKER) != (None, "unavailable")
    assert len(seen) == 1


async def test_cancelled_owner_releases_lock_for_the_next_client(store: Any) -> None:
    entered = asyncio.Event()

    async def handler(request: httpx.Request) -> httpx.Response:
        entered.set()
        await asyncio.Event().wait()
        return httpx.Response(200, json=PAYLOAD)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        owner = VirusTotalClient(api_key="test-key", store=store, client=http)
        task = asyncio.create_task(owner.report(ATTACKER))
        try:
            await asyncio.wait_for(entered.wait(), 1)
            assert await store.client.pttl(keys.enrichment_lock_key("vt", ATTACKER)) > 0
        finally:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
    client, seen = make_client(store, [])
    assert (await client.report(ATTACKER))[1] == "ok"
    assert len(seen) == 1


async def test_slow_cache_read_is_inside_the_lookup_deadline(store: Any, monkeypatch: Any) -> None:
    async def stalled(_key: str) -> None:
        await asyncio.Event().wait()

    monkeypatch.setattr(store, "get_value", stalled)
    client, seen = make_client(store, [])
    client._lookup_timeout = 0.02
    assert await asyncio.wait_for(client.report(ATTACKER), 0.5) == (None, "unavailable")
    assert seen == []


async def test_redis_failure_does_not_fall_back_to_http(store: Any, monkeypatch: Any) -> None:
    from redis.exceptions import ConnectionError as RedisConnectionError

    monkeypatch.setattr(store, "get_value", AsyncMock(side_effect=RedisConnectionError("offline")))
    client, seen = make_client(store, [])
    counter = metrics.ENRICHMENT_SKIPPED.labels(provider="virustotal", reason="store_error")
    before = counter._value.get()
    with pytest.raises(RedisConnectionError):
        await client.report(ATTACKER)
    assert counter._value.get() == before + 1
    assert seen == []


async def test_cache_write_failure_preserves_http_count_and_fail_soft_alert(
    store: Any, monkeypatch: Any, audit: Any, audit_stream: Any
) -> None:
    from redis.exceptions import ConnectionError as RedisConnectionError

    from opencanary_correlator.enrichment.service import IncidentEnricher

    client, seen = make_client(store, [])
    monkeypatch.setattr(
        store, "set_with_ttl", AsyncMock(side_effect=RedisConnectionError("offline"))
    )
    requests = metrics.ENRICHMENT_REQUESTS.labels(provider="virustotal", outcome="ok")
    errors = metrics.ENRICHMENT_SKIPPED.labels(provider="virustotal", reason="store_error")
    before_requests, before_errors = requests._value.get(), errors._value.get()
    enricher = IncidentEnricher(virustotal=client, audit=audit)

    result = await enricher.enrich(ATTACKER)

    assert result is not None and result.virus_total_status == "unavailable"
    assert len(seen) == 1
    assert requests._value.get() == before_requests + 1
    assert errors._value.get() == before_errors + 1
    records = [json.loads(line) for line in audit_stream.getvalue().splitlines()]
    assert any(
        record["action"] == "enrichment_failed"
        and record["details"].get("error_type") == "ConnectionError"
        for record in records
    )


async def test_lock_failure_never_bypasses_quota_or_sends_http(
    store: Any, monkeypatch: Any
) -> None:
    from redis.exceptions import ConnectionError as RedisConnectionError

    monkeypatch.setattr(store.client, "set", AsyncMock(side_effect=RedisConnectionError("offline")))
    reserve = AsyncMock(wraps=store.reserve_quota)
    monkeypatch.setattr(store, "reserve_quota", reserve)
    client, seen = make_client(store, [])
    with pytest.raises(RedisConnectionError):
        await client.report(ATTACKER)
    reserve.assert_not_awaited()
    assert seen == []


async def test_different_addresses_do_not_share_a_lock(store: Any) -> None:
    entered = asyncio.Event()
    release = asyncio.Event()
    seen: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if len(seen) == 2:
            entered.set()
        await release.wait()
        return httpx.Response(200, json=PAYLOAD)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = VirusTotalClient(api_key="test-key", store=store, client=http)
        tasks = [asyncio.create_task(client.report(ip)) for ip in (ATTACKER, "8.8.8.8")]
        try:
            await asyncio.wait_for(entered.wait(), 1)
            release.set()
            assert all(status == "ok" for _, status in await asyncio.gather(*tasks))
        finally:
            release.set()
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)


async def test_expired_owner_lease_can_be_recovered(store: Any) -> None:
    await store.set_with_ttl(keys.enrichment_lock_key("vt", ATTACKER), "dead-owner", ttl=0.03)
    client, seen = make_client(store, [])
    assert (await asyncio.wait_for(client.report(ATTACKER), 1))[1] == "ok"
    assert len(seen) == 1


async def test_disabled_positive_cache_allows_sequential_requests(store: Any) -> None:
    client, seen = make_client(store, [])
    client._cache_ttl = 0
    assert (await client.report(ATTACKER))[1] == "ok"
    assert (await client.report(ATTACKER))[1] == "ok"
    assert len(seen) == 2


async def test_http_timeout_and_stalled_unlock_are_bounded(store: Any, monkeypatch: Any) -> None:
    async def stalled(*_args: Any) -> None:
        await asyncio.Event().wait()

    monkeypatch.setattr(store, "_release_lock", stalled)
    async with httpx.AsyncClient(transport=httpx.MockTransport(stalled)) as http:
        client = VirusTotalClient(api_key="test-key", store=store, client=http, lookup_timeout=0.02)
        assert await asyncio.wait_for(client.report(ATTACKER), 0.5) == (None, "unavailable")
    ttl = await store.client.pttl(keys.enrichment_lock_key("vt", ATTACKER))
    assert 0 < ttl <= 1020


async def test_lease_covers_a_configured_long_lookup(store: Any) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        ttl = await store.client.pttl(keys.enrichment_lock_key("vt", ATTACKER))
        assert 60_000 < ttl <= 61_000
        return httpx.Response(200, json=PAYLOAD)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = VirusTotalClient(api_key="test-key", store=store, client=http, lookup_timeout=60)
        assert (await client.report(ATTACKER))[1] == "ok"
