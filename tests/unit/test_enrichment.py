"""Enricher: provider combination, budgets, audit records and cleanup."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest

from opencanary_correlator.enrichment.geo import GeoInspection, GeoLookup
from opencanary_correlator.enrichment.models import (
    Enrichment,
    GeoInfo,
    OpenCTIIndicator,
    VirusTotalReport,
    country_flag,
)
from opencanary_correlator.enrichment.opencti import OpenCTIClient, OpenCTICreateResult
from opencanary_correlator.enrichment.service import IncidentEnricher

ATTACKER = "74.22.3.178"
REPORT = VirusTotalReport(
    malicious=1, harmless=2, undetected=3, reputation=-5, checked="2026-10-26"
)
INFO = GeoInfo(
    country_code="US", country="United States", city="New York", asn=7922, as_org="Comcast"
)
INDICATOR = OpenCTIIndicator(
    id="indicator--1",
    pattern="[ipv4-addr:value = '74.22.3.178']",
    confidence=80,
    valid_from="2026-11-05T12:00:00.000Z",
    labels=("opencanary",),
)


class FakeGeo:
    """Geo provider stand-in."""

    def __init__(
        self,
        info: GeoInfo | None = INFO,
        error: Exception | None = None,
        failed: tuple[str, ...] = (),
    ) -> None:
        self.info = info
        self.error = error
        self.failed = failed
        self.closed = False
        self.calls: list[str] = []

    def lookup(self, ip: str) -> GeoInfo | None:
        self.calls.append(ip)
        if self.error is not None:
            raise self.error
        return self.info

    def inspect(self, ip: str) -> GeoInspection:
        return GeoInspection(self.lookup(ip), self.failed)

    def close(self) -> None:
        self.closed = True


class FakeVirusTotal:
    """VirusTotal stand-in with a scripted result."""

    def __init__(
        self,
        result: tuple[VirusTotalReport | None, str] = (REPORT, "ok"),
        *,
        error: Exception | None = None,
        delay: float = 0.0,
    ) -> None:
        self.result = result
        self.error = error
        self.delay = delay
        self.calls: list[str] = []
        self.closed = False

    async def report(self, ip: str) -> Any:
        self.calls.append(ip)
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.error is not None:
            raise self.error
        return self.result

    async def aclose(self) -> None:
        self.closed = True


class FakeOpenCTI:
    """OpenCTI stand-in that records how the enricher called it."""

    def __init__(
        self,
        indicator: OpenCTIIndicator | None = INDICATOR,
        status: str = "ok",
        *,
        create_mode: str = "off",
        error: Exception | None = None,
        delay: float = 0.0,
        result: OpenCTICreateResult | None = None,
    ) -> None:
        self.indicator = indicator
        self.status = status
        self._create_mode = create_mode
        self.error = error
        self.delay = delay
        self.result = result or OpenCTICreateResult(
            "existing" if indicator is not None else "created",
            indicator=indicator,
            status="ok" if status == "ok" else status,  # type: ignore[arg-type]
        )
        self.calls: list[tuple[str, str, dict[str, Any]]] = []
        self.closed = False

    @property
    def create_mode(self) -> str:
        """`off` makes the enricher use the read-only path."""
        return self._create_mode

    async def lookup(self, ip: str) -> tuple[OpenCTIIndicator | None, str]:
        self.calls.append(("lookup", ip, {}))
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.error is not None:
            raise self.error
        return self.indicator, self.status

    async def create_or_update(self, ip: str, **kwargs: Any) -> OpenCTICreateResult:
        self.calls.append(("create_or_update", ip, kwargs))
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.error is not None:
            raise self.error
        return self.result

    async def aclose(self) -> None:
        self.closed = True


def actions(audit_stream: Any) -> list[tuple[str, str]]:
    return [
        (record["action"], record["status"])
        for record in (
            json.loads(line) for line in audit_stream.getvalue().splitlines() if line.strip()
        )
    ]


async def test_both_providers_are_combined(audit: Any) -> None:
    geo = FakeGeo()
    virustotal = FakeVirusTotal()
    enricher = IncidentEnricher(geo=geo, virustotal=virustotal, audit=audit)  # type: ignore[arg-type]

    enrichment = await enricher.enrich(ATTACKER)

    assert enrichment is not None
    assert enrichment.geo is geo.info
    assert enrichment.virus_total == REPORT
    assert enrichment.virus_total_status == "ok"
    assert geo.calls == virustotal.calls == [ATTACKER]


@pytest.mark.parametrize("ip", ["10.0.0.5", "127.0.0.1", "::1", "not-an-ip"])
async def test_private_addresses_are_not_enriched(ip: str) -> None:
    geo = FakeGeo()
    virustotal = FakeVirusTotal()
    enricher = IncidentEnricher(geo=geo, virustotal=virustotal)  # type: ignore[arg-type]

    assert await enricher.enrich(ip) is None
    # No lookup, and no quota slot spent on an address that cannot be resolved.
    assert geo.calls == []
    assert virustotal.calls == []


async def test_an_unconfigured_enricher_reports_nothing() -> None:
    assert await IncidentEnricher().enrich(ATTACKER) is None
    assert IncidentEnricher().enabled is False


async def test_only_geo_configured_needs_no_key(audit_stream: Any) -> None:
    enricher = IncidentEnricher(geo=FakeGeo())  # type: ignore[arg-type]

    enrichment = await enricher.enrich(ATTACKER)

    assert enrichment is not None
    assert enrichment.geo is INFO
    assert enrichment.virus_total is None
    assert enrichment.virus_total_status is None


async def test_a_broken_geo_reader_is_audited_and_ignored(audit: Any, audit_stream: Any) -> None:
    geo = FakeGeo(error=RuntimeError("mmdb gone"))
    virustotal = FakeVirusTotal()
    enricher = IncidentEnricher(geo=geo, virustotal=virustotal, audit=audit)  # type: ignore[arg-type]

    enrichment = await enricher.enrich(ATTACKER)

    assert enrichment is not None
    assert enrichment.geo is None
    assert enrichment.virus_total == REPORT
    assert ("enrichment_failed", "error") in actions(audit_stream)


async def test_a_timeout_is_shown_as_unavailable(audit: Any, audit_stream: Any) -> None:
    enricher = IncidentEnricher(
        virustotal=FakeVirusTotal(delay=1.0),  # type: ignore[arg-type]
        audit=audit,
        timeout=0.01,
    )

    enrichment = await enricher.enrich(ATTACKER)

    assert enrichment is not None
    assert enrichment.virus_total is None
    assert enrichment.virus_total_status == "unavailable"
    assert ("enrichment_failed", "warning") in actions(audit_stream)

    records = [json.loads(line) for line in audit_stream.getvalue().splitlines()]
    assert records[-1]["details"]["reason"] == "timeout"


async def test_an_unexpected_exception_is_audited(audit: Any, audit_stream: Any) -> None:
    enricher = IncidentEnricher(
        virustotal=FakeVirusTotal(error=RuntimeError("boom")),  # type: ignore[arg-type]
        audit=audit,
    )

    enrichment = await enricher.enrich(ATTACKER)

    assert enrichment is not None
    assert enrichment.virus_total_status == "unavailable"
    records = [json.loads(line) for line in audit_stream.getvalue().splitlines()]
    assert records[-1]["details"]["error_type"] == "RuntimeError"


async def test_an_exhausted_quota_is_audited_as_skipped(audit: Any, audit_stream: Any) -> None:
    enricher = IncidentEnricher(
        virustotal=FakeVirusTotal((None, "quota")),  # type: ignore[arg-type]
        audit=audit,
    )

    enrichment = await enricher.enrich(ATTACKER)

    assert enrichment is not None
    assert enrichment.virus_total_status == "quota"
    assert ("enrichment_skipped", "info") in actions(audit_stream)


async def test_an_unavailable_provider_is_audited_without_geo(
    audit: Any, audit_stream: Any
) -> None:
    enricher = IncidentEnricher(
        virustotal=FakeVirusTotal((None, "unavailable")),  # type: ignore[arg-type]
        audit=audit,
    )

    enrichment = await enricher.enrich(ATTACKER)

    assert enrichment is not None
    assert enrichment.is_empty is False  # the status row is rendered
    assert ("enrichment_failed", "warning") in actions(audit_stream)


async def test_a_reader_failure_keeps_the_data_the_other_database_returned(
    audit: Any, audit_stream: Any
) -> None:
    """A broken ASN file must not throw away the country the city file found."""
    geo = FakeGeo(failed=("asn:RuntimeError",))
    enricher = IncidentEnricher(geo=geo, virustotal=FakeVirusTotal(), audit=audit)  # type: ignore[arg-type]

    enrichment = await enricher.enrich(ATTACKER)

    assert enrichment is not None
    assert enrichment.geo is INFO
    assert enrichment.virus_total == REPORT
    assert ("enrichment_failed", "error") in actions(audit_stream)
    records = [json.loads(line) for line in audit_stream.getvalue().splitlines()]
    assert records[-1]["details"]["failures"] == ["asn:RuntimeError"]


async def test_a_missing_geo_record_is_not_reported_as_a_failure(
    audit: Any, audit_stream: Any
) -> None:
    geo = FakeGeo(info=None, failed=())
    enricher = IncidentEnricher(geo=geo, audit=audit)  # type: ignore[arg-type]

    assert await enricher.enrich(ATTACKER) is None
    assert ("enrichment_failed", "error") not in actions(audit_stream)


async def test_nothing_known_yields_none() -> None:
    class EmptyGeo(FakeGeo):
        def lookup(self, ip: str) -> GeoInfo | None:
            return None

    enricher = IncidentEnricher(geo=EmptyGeo())  # type: ignore[arg-type]

    assert await enricher.enrich(ATTACKER) is None


async def test_close_releases_every_provider() -> None:
    geo = FakeGeo()
    virustotal = FakeVirusTotal()
    opencti = FakeOpenCTI()
    enricher = IncidentEnricher(geo=geo, virustotal=virustotal, opencti=opencti)  # type: ignore[arg-type]

    await enricher.aclose()

    assert geo.closed is True
    assert virustotal.closed is True
    assert opencti.closed is True


async def test_a_real_geo_lookup_runs_through_the_enricher(tmp_path: Any) -> None:
    """End-to-end shape check with the real `GeoLookup` object (fake readers)."""

    class Reader:
        def get(self, _ip: str) -> Any:
            return {
                "country": {"iso_code": "KZ", "names": {"en": "Kazakhstan"}},
                "city": {"names": {"en": "Almaty"}},
            }

        def close(self) -> None:
            return None

    enricher = IncidentEnricher(geo=GeoLookup(Reader()))

    # A globally routable address: enrichment deliberately skips reserved ranges.
    enrichment = await enricher.enrich("8.8.8.8")

    assert enrichment is not None
    assert enrichment.geo is not None
    assert enrichment.geo.location == "Kazakhstan, Almaty"


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        ("NL", "🇳🇱"),
        ("nl", "🇳🇱"),
        ("KZ", "🇰🇿"),
        # MMDB records are untrusted: anything that is not two ASCII letters has
        # no flag, and the row falls back to plain text.
        ("", ""),
        ("N", ""),
        ("NLD", ""),
        ("N1", ""),
        ("-1", ""),
        ("\u00e9\u00e9", ""),
    ],
)
def test_a_country_flag_comes_from_the_two_letter_code(code: str, expected: str) -> None:
    assert country_flag(code) == expected


def test_a_geo_record_without_a_code_renders_without_a_flag() -> None:
    """The flag is decoration: no code must not leave a stray space in the row."""
    info = GeoInfo(country="Kazakhstan")

    assert info.flag == ""
    assert info.location == "Kazakhstan"


def test_an_opencti_indicator_is_serialised_for_the_webhook() -> None:
    enrichment = Enrichment(
        opencti=OpenCTIIndicator(
            id="indicator--1",
            pattern="[ipv4-addr:value = '74.22.3.178']",
            confidence=80,
            created_at="2026-10-26T10:00:00Z",
            valid_from="2026-10-26T10:00:00Z",
            labels=("opencanary", "honeypot"),
        ),
        opencti_status="ok",
    )

    assert enrichment.is_empty is False
    assert enrichment.to_payload()["opencti"] == {
        "id": "indicator--1",
        "pattern": "[ipv4-addr:value = '74.22.3.178']",
        "confidence": 80,
        "created_at": "2026-10-26T10:00:00Z",
        "valid_from": "2026-10-26T10:00:00Z",
        "labels": ["opencanary", "honeypot"],
    }


def test_a_missing_opencti_indicator_is_reported_as_a_status() -> None:
    """`not_found` is an answer, not missing data, so it is rendered."""
    enrichment = Enrichment(opencti_status="not_found")

    assert enrichment.is_empty is False
    assert enrichment.to_payload() == {"opencti_status": "not_found"}


def test_an_enrichment_without_opencti_stays_empty() -> None:
    enrichment = Enrichment()

    assert enrichment.is_empty is True
    assert enrichment.to_payload() == {}


# --- OpenCTI inside the enricher --------------------------------------------


async def test_opencti_is_combined_with_the_other_providers(audit: Any) -> None:
    opencti = FakeOpenCTI()
    enricher = IncidentEnricher(
        geo=FakeGeo(),
        virustotal=FakeVirusTotal(),
        opencti=opencti,  # type: ignore[arg-type]
        audit=audit,
    )

    enrichment = await enricher.enrich(ATTACKER)

    assert enrichment is not None
    assert enrichment.geo is INFO
    assert enrichment.virus_total == REPORT
    assert enrichment.opencti == INDICATOR
    assert enrichment.opencti_status == "ok"
    assert opencti.calls == [("lookup", ATTACKER, {})]


async def test_the_creation_mode_receives_the_incident_time_and_policy(audit: Any) -> None:
    moment = datetime(2026, 11, 5, 12, 0, tzinfo=UTC)
    opencti = FakeOpenCTI(
        create_mode="always",
        result=OpenCTICreateResult("updated", indicator=INDICATOR),
    )
    enricher = IncidentEnricher(
        opencti=opencti,  # type: ignore[arg-type]
        opencti_confidence=90,
        opencti_labels=("opencanary", "honeypot"),
        audit=audit,
    )

    enrichment = await enricher.enrich(ATTACKER, occurred_at=moment)

    assert enrichment is not None
    assert enrichment.opencti == INDICATOR
    assert opencti.calls == [
        (
            "create_or_update",
            ATTACKER,
            {"confidence": 90, "labels": ("opencanary", "honeypot"), "valid_from": moment},
        )
    ]


async def test_a_broken_opencti_client_keeps_the_other_providers(
    audit: Any, audit_stream: Any
) -> None:
    enricher = IncidentEnricher(
        geo=FakeGeo(),
        virustotal=FakeVirusTotal(),
        opencti=FakeOpenCTI(error=RuntimeError("boom")),  # type: ignore[arg-type]
        audit=audit,
    )

    enrichment = await enricher.enrich(ATTACKER)

    assert enrichment is not None
    assert enrichment.geo is INFO
    assert enrichment.virus_total == REPORT
    assert enrichment.opencti is None
    assert enrichment.opencti_status == "unavailable"
    records = [json.loads(line) for line in audit_stream.getvalue().splitlines()]
    assert records[-1]["details"] == {"provider": "opencti", "error_type": "RuntimeError"}


@pytest.mark.parametrize("status", ["unavailable", "unauthorized"])
async def test_an_unanswered_opencti_lookup_is_shown_as_a_status(
    audit: Any, audit_stream: Any, status: str
) -> None:
    enricher = IncidentEnricher(
        opencti=FakeOpenCTI(indicator=None, status=status),  # type: ignore[arg-type]
        audit=audit,
    )

    enrichment = await enricher.enrich(ATTACKER)

    assert enrichment is not None
    assert enrichment.opencti is None
    assert enrichment.opencti_status == status
    assert ("enrichment_failed", "error" if status == "unauthorized" else "warning") in actions(
        audit_stream
    )


async def test_a_missing_indicator_is_reported_as_not_found(audit: Any) -> None:
    enricher = IncidentEnricher(
        opencti=FakeOpenCTI(indicator=None, status="not_found"),  # type: ignore[arg-type]
        audit=audit,
    )

    enrichment = await enricher.enrich(ATTACKER)

    assert enrichment is not None
    assert enrichment.opencti is None
    assert enrichment.opencti_status == "not_found"


async def test_a_failed_indicator_write_is_shown_as_unavailable(audit: Any) -> None:
    """A failed create must not look like "OpenCTI knows nothing" either."""
    result = OpenCTICreateResult("failed", status="unavailable", reason="http_error")
    enricher = IncidentEnricher(
        opencti=FakeOpenCTI(create_mode="missing", result=result),  # type: ignore[arg-type]
        audit=audit,
    )

    enrichment = await enricher.enrich(ATTACKER)

    assert enrichment is not None
    assert enrichment.opencti is None
    assert enrichment.opencti_status == "unavailable"


async def test_a_disabled_client_adds_no_row(audit: Any) -> None:
    enricher = IncidentEnricher(
        opencti=FakeOpenCTI(indicator=None, status="disabled"),  # type: ignore[arg-type]
        audit=audit,
    )

    assert await enricher.enrich(ATTACKER) is None


async def test_opencti_alone_enables_the_enricher() -> None:
    enricher = IncidentEnricher(opencti=FakeOpenCTI())  # type: ignore[arg-type]

    assert enricher.enabled is True


async def test_a_slow_opencti_is_bounded_by_the_pass_budget(audit: Any) -> None:
    enricher = IncidentEnricher(
        virustotal=FakeVirusTotal(),
        opencti=FakeOpenCTI(delay=1.0),  # type: ignore[arg-type]
        audit=audit,
        timeout=0.05,
    )

    enrichment = await enricher.enrich(ATTACKER)

    assert enrichment is not None
    assert enrichment.virus_total == REPORT
    assert enrichment.opencti_status == "unavailable"


async def test_two_alerts_for_one_address_query_opencti_once(store: Any, audit: Any) -> None:
    """The client's Redis cache is what keeps a burst of alerts to one request."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(
            200,
            json={
                "data": {
                    "indicators": {"edges": [{"node": {"id": "indicator--1", "confidence": 80}}]}
                }
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = OpenCTIClient(
            url="https://opencti.example",
            token="test-token",
            store=store,
            client=http,
            audit=audit,
        )
        enricher = IncidentEnricher(opencti=client, audit=audit)
        first = await enricher.enrich(ATTACKER)
        second = await enricher.enrich(ATTACKER)

    assert first == second
    assert first is not None and first.opencti is not None
    assert first.opencti.id == "indicator--1"
    assert len(seen) == 1
