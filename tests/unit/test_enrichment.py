"""Enricher: provider combination, budgets, audit records and cleanup."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest

from opencanary_correlator.enrichment.geo import GeoLookup
from opencanary_correlator.enrichment.models import GeoInfo, VirusTotalReport
from opencanary_correlator.enrichment.service import IncidentEnricher

ATTACKER = "74.22.3.178"
REPORT = VirusTotalReport(
    malicious=1, harmless=2, undetected=3, reputation=-5, checked="2026-10-26"
)
INFO = GeoInfo(
    country_code="US", country="United States", city="New York", asn=7922, as_org="Comcast"
)


class FakeGeo:
    """Geo provider stand-in."""

    def __init__(self, info: GeoInfo | None = INFO, error: Exception | None = None) -> None:
        self.info = info
        self.error = error
        self.closed = False
        self.calls: list[str] = []

    def lookup(self, ip: str) -> GeoInfo | None:
        self.calls.append(ip)
        if self.error is not None:
            raise self.error
        return self.info

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


async def test_nothing_known_yields_none() -> None:
    class EmptyGeo(FakeGeo):
        def lookup(self, ip: str) -> GeoInfo | None:
            return None

    enricher = IncidentEnricher(geo=EmptyGeo())  # type: ignore[arg-type]

    assert await enricher.enrich(ATTACKER) is None


async def test_close_releases_every_provider() -> None:
    geo = FakeGeo()
    virustotal = FakeVirusTotal()
    enricher = IncidentEnricher(geo=geo, virustotal=virustotal)  # type: ignore[arg-type]

    await enricher.aclose()

    assert geo.closed is True
    assert virustotal.closed is True


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

    enrichment = await enricher.enrich("89.126.202.164")

    assert enrichment is not None
    assert enrichment.geo is not None
    assert enrichment.geo.location == "Kazakhstan, Almaty"
