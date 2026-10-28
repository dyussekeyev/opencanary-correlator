"""VirusTotal client: parsing, cache, quota windows and failure modes."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

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
        (httpx.Response(401), "unavailable"),
        (httpx.Response(500), "unavailable"),
        (httpx.ConnectError("boom"), "unavailable"),
        (httpx.Response(200, json={"data": {}}), "ok"),
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
    client, seen = make_client(store, [httpx.Response(200, json={"data": {}})])
    try:
        assert (await client.report(ATTACKER))[1] == "ok"
        assert (await client.report(ATTACKER))[1] == "ok"
    finally:
        await client.aclose()

    assert len(seen) == 1
    ttl_ms = await store.client.pttl(keys.enrichment_cache_key("vt", ATTACKER))
    assert 0 < ttl_ms <= 3_600_000
