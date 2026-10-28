"""Attacker-IP enrichment: offline geo/ASN and VirusTotal reputation.

Both providers are optional and off by default. The engine attaches the result
to the incident it is about to dispatch; nothing is stored in Redis beyond a
per-address cache and the quota counters.
"""

from __future__ import annotations

from opencanary_correlator.enrichment.geo import GeoLookup, GeoLookupError, public_address
from opencanary_correlator.enrichment.models import (
    Enrichment,
    GeoInfo,
    VirusTotalReport,
    VirusTotalStatus,
)
from opencanary_correlator.enrichment.service import DEFAULT_ENRICHMENT_TIMEOUT, IncidentEnricher
from opencanary_correlator.enrichment.virustotal import QuotaLimits, VirusTotalClient

__all__ = [
    "DEFAULT_ENRICHMENT_TIMEOUT",
    "Enrichment",
    "GeoInfo",
    "GeoLookup",
    "GeoLookupError",
    "IncidentEnricher",
    "QuotaLimits",
    "VirusTotalClient",
    "VirusTotalReport",
    "VirusTotalStatus",
    "public_address",
]
