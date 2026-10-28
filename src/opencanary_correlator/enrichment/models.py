"""Values produced by attacker-IP enrichment.

These are plain data: the engine attaches an :class:`Enrichment` to the incident
it is about to dispatch, and the alert renderer decides how much of it a detail
level shows. Nothing here is persisted in the incident hash, so a change to the
shape never migrates stored incidents.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

#: Outcome of the VirusTotal lookup for one address.
#: ``ok`` has a report, ``quota`` means every free-tier window was spent, and
#: ``unavailable`` covers timeouts, HTTP errors and a missing/invalid key.
VirusTotalStatus = Literal["ok", "quota", "unavailable"]


class GeoInfo(BaseModel):
    """Country, city and network for one address."""

    model_config = ConfigDict(frozen=True)

    country_code: str = ""
    country: str = ""
    city: str = ""
    asn: int | None = None
    as_org: str = ""

    @property
    def is_empty(self) -> bool:
        """True when the database had nothing useful for this address."""
        return not (self.country_code or self.country or self.city or self.asn or self.as_org)

    @property
    def location(self) -> str:
        """`Netherlands, Amsterdam`, or `NL` when only the code is known."""
        country = self.country or self.country_code
        if country and self.city:
            return f"{country}, {self.city}"
        return country or self.city

    @property
    def network(self) -> str:
        """`AS202425 IP Volume inc`, or `AS202425` when the name is missing."""
        if self.asn and self.as_org:
            return f"AS{self.asn} {self.as_org}"
        if self.asn:
            return f"AS{self.asn}"
        return self.as_org


class VirusTotalReport(BaseModel):
    """Detection ratio and community score for one address."""

    model_config = ConfigDict(frozen=True)

    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    reputation: int | None = None
    #: Date (UTC, `YYYY-MM-DD`) of the last analysis VirusTotal reports.
    checked: str | None = None

    @property
    def total(self) -> int:
        """Engines that returned a verdict."""
        return self.malicious + self.suspicious + self.harmless + self.undetected

    @property
    def detections(self) -> int:
        """Engines that flagged the address in any way."""
        return self.malicious + self.suspicious


class Enrichment(BaseModel):
    """Everything known about one attacker address at alert time."""

    model_config = ConfigDict(frozen=True)

    geo: GeoInfo | None = None
    virus_total: VirusTotalReport | None = None
    virus_total_status: VirusTotalStatus | None = None

    @property
    def is_empty(self) -> bool:
        """True when nothing would be rendered."""
        if self.geo is not None and not self.geo.is_empty:
            return False
        return self.virus_total is None and self.virus_total_status is None


__all__ = ["Enrichment", "GeoInfo", "VirusTotalReport", "VirusTotalStatus"]
