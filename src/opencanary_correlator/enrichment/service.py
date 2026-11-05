"""Combine the available enrichment sources for one incident.

The enricher runs on the dispatch path, so it is bounded twice: each provider
gets its own timeout and the whole call has a budget. A provider that is slow,
throttled or broken must never delay the alert itself — a reputation lookup is
useful context, not a reason to lose the notification.
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from datetime import datetime
from typing import Final, Literal

from opencanary_correlator import metrics
from opencanary_correlator.audit import AuditLogger
from opencanary_correlator.core.service_messages import ServiceKind, ServiceNotifier
from opencanary_correlator.enrichment.geo import GeoLookup, public_address
from opencanary_correlator.enrichment.models import (
    Enrichment,
    GeoInfo,
    OpenCTIIndicator,
    OpenCTIStatus,
    VirusTotalReport,
    VirusTotalStatus,
)
from opencanary_correlator.enrichment.opencti import OpenCTIClient
from opencanary_correlator.enrichment.virustotal import VirusTotalClient

#: Upper bound for a whole enrichment pass, well below the dispatch timeout.
DEFAULT_ENRICHMENT_TIMEOUT: Final[float] = 6.0


class IncidentEnricher:
    """Look up geo, VirusTotal and OpenCTI data for an attacker address."""

    def __init__(
        self,
        *,
        geo: GeoLookup | None = None,
        virustotal: VirusTotalClient | None = None,
        opencti: OpenCTIClient | None = None,
        opencti_confidence: int = 50,
        opencti_labels: Sequence[str] = (),
        audit: AuditLogger | None = None,
        timeout: float = DEFAULT_ENRICHMENT_TIMEOUT,
        notifier: ServiceNotifier | None = None,
    ) -> None:
        self._geo = geo
        self._virustotal = virustotal
        self._opencti = opencti
        # Copied once: the settings list must not change under a running process.
        self._opencti_confidence = opencti_confidence
        self._opencti_labels = tuple(opencti_labels)
        self._audit = audit
        self._timeout = timeout
        # Service messages are best-effort: a degraded notifier must never turn a
        # provider problem into a lost alert.
        self._notifier = notifier

    async def aclose(self) -> None:
        """Release the provider resources (HTTP client, MMDB readers)."""
        if self._virustotal is not None:
            await self._virustotal.aclose()
        if self._opencti is not None:
            await self._opencti.aclose()
        if self._geo is not None:
            self._geo.close()

    @property
    def enabled(self) -> bool:
        """True when at least one provider is configured."""
        return self._geo is not None or self._virustotal is not None or self._opencti is not None

    async def enrich(
        self, src_host: str, *, occurred_at: datetime | None = None
    ) -> Enrichment | None:
        """Return what is known about `src_host`, or None when nothing is.

        Private, loopback and invalid addresses are skipped entirely: showing
        "Netherlands" for `10.0.0.5` would be worse than showing nothing, and the
        address is not worth a quota slot.

        `occurred_at` is the incident time and becomes the STIX `valid_from` of an
        indicator OpenCTI creates. One deadline is shared by every provider, so
        three slow sources cannot add up to three budgets.
        """
        if not self.enabled or public_address(src_host) is None:
            return None

        deadline = asyncio.get_running_loop().time() + self._timeout
        geo = await self._lookup_geo(src_host)
        report = None
        status: VirusTotalStatus | None = None
        if self._virustotal is not None:
            report, status = await self._lookup_virustotal(src_host, deadline)
        indicator: OpenCTIIndicator | None = None
        opencti_status: OpenCTIStatus | None = None
        if self._opencti is not None:
            indicator, opencti_status = await self._lookup_opencti(src_host, deadline, occurred_at)

        enrichment = Enrichment(
            geo=geo,
            virus_total=report,
            virus_total_status=status,
            opencti=indicator,
            opencti_status=opencti_status,
        )
        return None if enrichment.is_empty else enrichment

    async def _lookup_geo(self, src_host: str) -> GeoInfo | None:
        if self._geo is None:
            return None
        try:
            inspection = self._geo.inspect(src_host)
        except Exception as exc:  # a broken lookup must not stop the alert
            metrics.ENRICHMENT_GEO.labels(result="error").inc()
            self._emit(
                "enrichment_failed", "error", {"provider": "geo", "error_type": type(exc).__name__}
            )
            await self._geo_unavailable([type(exc).__name__])
            return None
        if inspection.failed:
            # A reader that raises is not "the database knows nothing": the
            # alert still goes out with whatever the other file returned, and
            # the operator learns which one to check. A missing record is just
            # traffic and stays silent.
            metrics.ENRICHMENT_GEO.labels(result="error").inc()
            self._emit(
                "enrichment_failed",
                "error",
                {"provider": "geo", "failures": list(inspection.failed)},
            )
            await self._geo_unavailable(list(inspection.failed))
            return inspection.info
        metrics.ENRICHMENT_GEO.labels(result="hit" if inspection.info else "no_match").inc()
        return inspection.info

    async def _geo_unavailable(self, failures: list[str]) -> None:
        """Tell the operator once per cooldown; enrichment never raises for this."""
        await self._notify(
            ServiceKind.GEO_UNAVAILABLE,
            title="GeoIP lookup failed",
            lines=(
                f"The database raised {failures[0]}",
                "Check OCC_GEOIP_CITY_DB and OCC_GEOIP_ASN_DB",
                "Alerts continue with the remaining geo data",
            ),
            subject="geoip",
        )

    async def _lookup_virustotal(
        self, src_host: str, deadline: float
    ) -> tuple[VirusTotalReport | None, VirusTotalStatus]:
        client = self._virustotal
        if client is None:  # pragma: no cover - guarded by `enrich`
            return None, "unavailable"
        try:
            report, status = await asyncio.wait_for(
                client.report(src_host), timeout=self._remaining(deadline)
            )
        except TimeoutError:
            self._emit(
                "enrichment_failed", "warning", {"provider": "virustotal", "reason": "timeout"}
            )
            await self._notify_virustotal("unavailable", detail="timeout")
            return None, "unavailable"
        except Exception as exc:  # defensive: the client is documented not to raise
            self._emit(
                "enrichment_failed",
                "error",
                {"provider": "virustotal", "error_type": type(exc).__name__},
            )
            await self._notify_virustotal("unavailable", detail=type(exc).__name__)
            return None, "unavailable"
        if status == "quota":
            self._emit("enrichment_skipped", "info", {"provider": "virustotal", "reason": "quota"})
            await self._notify_virustotal("quota", window=await self._quota_window(client))
        elif status == "unauthorized":
            # The alert cannot say "the key is wrong": nothing is known about the
            # attacker, so it looks like "no detections". The operator is told
            # through a service message instead.
            self._emit(
                "enrichment_failed",
                "error",
                {"provider": "virustotal", "reason": "key_rejected"},
            )
            await self._notify_virustotal("unauthorized")
            return None, "unavailable"
        elif status == "unavailable":
            self._emit(
                "enrichment_failed",
                "warning",
                {"provider": "virustotal", "reason": "unavailable"},
            )
            await self._notify_virustotal("unavailable", detail="unavailable")
        return report, status

    async def _lookup_opencti(
        self,
        src_host: str,
        deadline: float,
        occurred_at: datetime | None,
    ) -> tuple[OpenCTIIndicator | None, OpenCTIStatus | None]:
        """Read or write the OpenCTI indicator, inside the pass budget.

        Both paths are bounded by the time left and never raise: a platform that
        is down, slow or refuses the token changes what the alert says, not
        whether it is delivered.
        """
        client = self._opencti
        if client is None:  # pragma: no cover - guarded by `enrich`
            return None, None
        indicator: OpenCTIIndicator | None
        status: OpenCTIStatus
        outcome = ""
        try:
            if client.create_mode == "off":
                indicator, status = await asyncio.wait_for(
                    client.lookup(src_host), timeout=self._remaining(deadline)
                )
            else:
                created = await asyncio.wait_for(
                    client.create_or_update(
                        src_host,
                        confidence=self._opencti_confidence,
                        labels=self._opencti_labels,
                        valid_from=occurred_at,
                    ),
                    timeout=self._remaining(deadline),
                )
                indicator, status = created.indicator, created.status
                outcome = created.outcome
        except TimeoutError:
            self._emit("enrichment_failed", "warning", {"provider": "opencti", "reason": "timeout"})
            return None, "unavailable"
        except Exception as exc:  # defensive: the client is documented not to raise
            self._emit(
                "enrichment_failed",
                "error",
                {"provider": "opencti", "error_type": type(exc).__name__},
            )
            return None, "unavailable"
        if status == "disabled":
            # Nothing was asked and nothing was written; no row in the alert.
            return None, None
        details: dict[str, object] = {"status": status, "found": indicator is not None}
        if outcome:
            details["outcome"] = outcome
        self._emit("opencti_lookup", "info", details)
        if status == "unauthorized":
            self._emit(
                "enrichment_failed", "error", {"provider": "opencti", "reason": "unauthorized"}
            )
        elif status == "unavailable":
            self._emit(
                "enrichment_failed", "warning", {"provider": "opencti", "reason": "unavailable"}
            )
        return indicator, status

    @staticmethod
    def _remaining(deadline: float) -> float:
        """Seconds left in the pass budget; `wait_for` rejects a zero timeout."""
        return max(0.001, deadline - asyncio.get_running_loop().time())

    async def _quota_window(self, client: VirusTotalClient) -> str | None:
        """Ask which free-tier window is spent, without letting that answer fail."""
        try:
            return await client.exhausted_window()
        except Exception:  # pragma: no cover - a read-only probe
            return None

    async def _notify_virustotal(
        self, reason: str, *, window: str | None = None, detail: str | None = None
    ) -> None:
        """Turn one VirusTotal outcome into the matching service message."""
        if reason == "quota":
            period = window or "free-tier"
            await self._notify(
                ServiceKind.VIRUSTOTAL_QUOTA,
                title="VirusTotal quota is exhausted",
                lines=(
                    f"The {period} window is spent",
                    "Lookups resume when the window rolls over; alerts continue without reputation",
                ),
                subject=f"virustotal:{period}",
            )
            return
        if reason == "unauthorized":
            await self._notify(
                ServiceKind.VIRUSTOTAL_KEY_REJECTED,
                title="VirusTotal rejected the API key",
                lines=(
                    "The API answered 401 or 403 for every lookup",
                    "Check OCC_VIRUSTOTAL_API_KEY and that the key is still enabled",
                ),
                subject="virustotal:key",
            )
            return
        failure = detail or reason
        await self._notify(
            ServiceKind.VIRUSTOTAL_UNAVAILABLE,
            title="VirusTotal is unreachable",
            lines=(
                f"Last failure: {failure}",
                "Alerts continue without reputation data",
            ),
            subject="virustotal:unavailable",
        )

    async def _notify(
        self,
        kind: ServiceKind,
        *,
        title: str,
        lines: tuple[str, ...],
        subject: str,
    ) -> None:
        """Send a service message, never letting the notifier break enrichment."""
        if self._notifier is None:
            return
        try:
            await self._notifier.notify(kind, title=title, lines=lines, subject=subject)
        except Exception:  # pragma: no cover - the notifier is documented not to raise
            return

    def _emit(
        self,
        action: str,
        status: Literal["info", "warning", "error", "success"],
        details: dict[str, object],
    ) -> None:
        if self._audit is not None:
            self._audit.emit(action, status, details)


__all__ = ["DEFAULT_ENRICHMENT_TIMEOUT", "IncidentEnricher"]
