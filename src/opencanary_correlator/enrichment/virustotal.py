"""VirusTotal reputation for attacker addresses, inside the free-tier limits.

The public free API allows 4 lookups per minute, 500 per day and 15.5K per
month. A correlator that ignored those numbers would spend its budget on the
first scanner of the night and then deliver alerts with no reputation at all, so
every lookup goes through three fixed windows in Redis and a per-address cache.

The API key is sent in the `x-apikey` header, never in the URL, so it cannot end
up in a log line the way a Telegram bot token does.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final

import httpx
from pydantic import SecretStr

from opencanary_correlator.enrichment.models import VirusTotalReport, VirusTotalStatus
from opencanary_correlator.storage import keys
from opencanary_correlator.storage.redis_store import RedisStore

VIRUSTOTAL_ENDPOINT: Final[str] = "https://www.virustotal.com/api/v3/ip_addresses/"

#: A verdict that VirusTotal has no data for is cached briefly: re-asking every
#: minute would burn the daily budget on addresses that will not resolve soon.
_MISS_CACHE_TTL: Final[float] = 3600.0
_MONTH_SECONDS: Final[float] = 31 * 24 * 3600.0


@dataclass(frozen=True, slots=True)
class QuotaLimits:
    """The published free-tier limits, in calls per window."""

    per_minute: int = 4
    per_day: int = 500
    per_month: int = 15_500


class VirusTotalClient:
    """Look up one address, honouring the quota and a Redis cache."""

    name = "virustotal"

    def __init__(
        self,
        *,
        api_key: SecretStr | str,
        store: RedisStore,
        cache_ttl: float = 7 * 24 * 3600.0,
        timeout: float = 5.0,
        limits: QuotaLimits | None = None,
        client: httpx.AsyncClient | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._api_key = api_key.get_secret_value() if isinstance(api_key, SecretStr) else api_key
        self._store = store
        self._cache_ttl = cache_ttl
        self._client = client if client is not None else httpx.AsyncClient(timeout=timeout)
        self._owns_client = client is None
        self._limits = limits or QuotaLimits()
        self._clock = clock

    async def aclose(self) -> None:
        """Close the HTTP client if this client created it."""
        if self._owns_client:
            await self._client.aclose()

    async def report(self, ip: str) -> tuple[VirusTotalReport | None, VirusTotalStatus]:
        """Return the report and the outcome, never raising.

        The caller renders `quota` and `unavailable` as a status line, so a
        throttled or failing provider is visible in the alert instead of looking
        like an address with no detections.
        """
        hit, cached = await self._read_cache(ip)
        if hit:
            return cached, "ok"

        if not await self._reserve():
            return None, "quota"

        try:
            response = await self._client.get(
                f"{VIRUSTOTAL_ENDPOINT}{ip}", headers={"x-apikey": self._api_key}
            )
        except httpx.HTTPError:
            return None, "unavailable"

        if response.status_code == 429:
            # Reserved slot spent by somebody else sharing the key, or our own
            # counters drifted from the server's view. Either way: stop asking.
            return None, "quota"
        if response.status_code != 200:
            return None, "unavailable"

        try:
            payload = response.json()
            report = _parse(payload)
        except (ValueError, TypeError, KeyError, AttributeError):
            return None, "unavailable"
        if report is None:
            await self._write_cache(ip, None, ttl=_MISS_CACHE_TTL)
            return None, "ok"
        await self._write_cache(ip, report, ttl=self._cache_ttl)
        return report, "ok"

    # --- Quota --------------------------------------------------------------

    async def _reserve(self) -> bool:
        """Take one slot in the minute, day and month windows."""
        now = datetime.fromtimestamp(self._clock(), tz=UTC)
        limits = self._limits
        windows = [
            (
                keys.quota_key("virustotal", "minute", now.strftime("%Y%m%d%H%M")),
                limits.per_minute,
                60_000,
            ),
            (
                keys.quota_key("virustotal", "day", now.strftime("%Y%m%d")),
                limits.per_day,
                24 * 3600 * 1000,
            ),
            (
                keys.quota_key("virustotal", "month", now.strftime("%Y%m")),
                limits.per_month,
                int(_MONTH_SECONDS * 1000),
            ),
        ]
        return await self._store.reserve_quota(windows)

    # --- Cache --------------------------------------------------------------

    async def _read_cache(self, ip: str) -> tuple[bool, VirusTotalReport | None]:
        """Return `(hit, report)`; a cached empty verdict is a hit with no report.

        "VirusTotal has no data for this address" is a real answer worth keeping:
        re-asking every minute would spend the daily budget on addresses that will
        not resolve any time soon.
        """
        raw = await self._store.get_value(keys.enrichment_cache_key("vt", ip))
        if not raw:
            return False, None
        try:
            payload = json.loads(raw)
        except ValueError:
            return False, None
        if payload is None:
            return True, None
        try:
            return True, VirusTotalReport.model_validate(payload)
        except ValueError:
            return False, None

    async def _write_cache(self, ip: str, report: VirusTotalReport | None, *, ttl: float) -> None:
        payload = json.dumps(report.model_dump() if report is not None else None)
        await self._store.set_with_ttl(keys.enrichment_cache_key("vt", ip), payload, ttl=ttl)


def _parse(payload: object) -> VirusTotalReport | None:
    """Turn a VirusTotal IP object into a report, or None when it has no data."""
    if not isinstance(payload, dict):
        return None
    data = payload.get("data")
    if not isinstance(data, dict):
        return None
    attributes = data.get("attributes")
    if not isinstance(attributes, dict):
        return None
    stats = attributes.get("last_analysis_stats")
    if not isinstance(stats, dict):
        return None

    def count(name: str) -> int:
        try:
            return max(0, int(stats.get(name) or 0))
        except (TypeError, ValueError):
            return 0

    reputation = attributes.get("reputation")
    try:
        reputation_value = int(reputation) if reputation is not None else None
    except (TypeError, ValueError):
        reputation_value = None

    return VirusTotalReport(
        malicious=count("malicious"),
        suspicious=count("suspicious"),
        harmless=count("harmless"),
        undetected=count("undetected"),
        reputation=reputation_value,
        checked=_analysis_date(attributes.get("last_analysis_date")),
    )


def _analysis_date(value: object) -> str | None:
    """Render VirusTotal's epoch as `YYYY-MM-DD`, ignoring anything unexpected."""
    if not isinstance(value, (int, float, str)):
        return None
    try:
        return datetime.fromtimestamp(int(value), tz=UTC).strftime("%Y-%m-%d")
    except (TypeError, ValueError, OSError, OverflowError):
        return None


__all__ = ["QuotaLimits", "VirusTotalClient"]
