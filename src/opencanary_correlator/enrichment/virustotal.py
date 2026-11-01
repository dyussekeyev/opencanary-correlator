"""VirusTotal reputation for attacker addresses, inside the free-tier limits.

The public free API allows 4 lookups per minute, 500 per day and 15.5K per
month. A correlator that ignored those numbers would spend its budget on the
first scanner of the night and then deliver alerts with no reputation at all, so
every lookup goes through three fixed windows in Redis and a per-address cache.

The API key is sent in the `x-apikey` header, never in the URL, so it cannot end
up in a log line the way a Telegram bot token does.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import time
from collections.abc import Callable
from contextlib import AsyncExitStack
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Final, Literal

import httpx
from pydantic import BaseModel, ConfigDict, SecretStr, ValidationError
from redis.exceptions import RedisError

from opencanary_correlator import metrics
from opencanary_correlator.audit import AuditLogger
from opencanary_correlator.enrichment.geo import public_address
from opencanary_correlator.enrichment.models import VirusTotalReport
from opencanary_correlator.storage import keys
from opencanary_correlator.storage.redis_store import RedisStore

VIRUSTOTAL_ENDPOINT: Final[str] = "https://www.virustotal.com/api/v3/ip_addresses/"

#: Outcome of one lookup, including the case the alert cannot express: a key the
#: API refuses. The enricher reports that as `unavailable` in the alert (nothing
#: about the attacker is known) and as a service message to the operator, because
#: "no reputation" and "your key is wrong" are different problems.
LookupStatus = Literal["ok", "quota", "unavailable", "unauthorized"]

#: A verdict that VirusTotal has no data for is cached briefly: re-asking every
#: minute would burn the daily budget on addresses that will not resolve soon.
_MONTH_SECONDS: Final[float] = 31 * 24 * 3600.0


class _Cooldown(BaseModel):
    """Validated Redis marker, never a reputation verdict."""

    model_config = ConfigDict(strict=True, extra="forbid")
    status: Literal["unauthorized", "quota", "unavailable"]


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
        lookup_timeout: float = 6.0,
        miss_cache_ttl: float = 3600.0,
        error_cooldown: float = 30.0,
        auth_cooldown: float = 300.0,
        rate_limit_cooldown: float = 60.0,
        max_retry_after: float = 3600.0,
        limits: QuotaLimits | None = None,
        client: httpx.AsyncClient | None = None,
        clock: Callable[[], float] = time.time,
        audit: AuditLogger | None = None,
    ) -> None:
        self._api_key = api_key.get_secret_value() if isinstance(api_key, SecretStr) else api_key
        self._store = store
        self._cache_ttl = cache_ttl
        self._lookup_timeout = lookup_timeout
        self._http_timeout = timeout
        self._miss_cache_ttl = miss_cache_ttl
        self._error_cooldown = error_cooldown
        self._auth_cooldown = auth_cooldown
        self._rate_limit_cooldown = rate_limit_cooldown
        self._max_retry_after = max_retry_after
        self._client = client if client is not None else httpx.AsyncClient(timeout=timeout)
        self._owns_client = client is None
        self._limits = limits or QuotaLimits()
        self._clock = clock
        self._audit = audit

    async def aclose(self) -> None:
        """Close the HTTP client if this client created it."""
        if self._owns_client:
            await self._client.aclose()

    async def report(self, ip: str) -> tuple[VirusTotalReport | None, LookupStatus]:
        """Return a report within the lookup budget; cancellation propagates.

        Redis failures propagate to the enricher's audit/fail-soft boundary:
        bypassing an unavailable cache or lock would bypass the quota as well.

        The caller renders `quota` and `unavailable` as a status line, so a
        throttled or failing provider is visible in the alert instead of looking
        like an address with no detections.
        """
        address = public_address(ip)
        if address is None:
            return None, "unavailable"
        ip = str(address)
        deadline = asyncio.get_running_loop().time() + self._lookup_timeout
        try:
            async with asyncio.timeout_at(deadline):
                return await self._singleflight(ip, deadline)
        except TimeoutError:
            self._skip("singleflight_timeout")
            return None, "unavailable"
        except RedisError:
            self._skip("store_error")
            raise

    def _skip(self, reason: str) -> None:
        metrics.ENRICHMENT_SKIPPED.labels(provider=self.name, reason=reason).inc()
        if self._audit is not None:
            self._audit.emit(
                "enrichment_request_skipped", "info", {"provider": self.name, "reason": reason}
            )

    async def _singleflight(
        self, ip: str, deadline: float
    ) -> tuple[VirusTotalReport | None, LookupStatus]:
        loop = asyncio.get_running_loop()
        initial = True
        while True:
            hit, cached = await self._read_cache(ip)
            if initial:
                result = ("negative_hit" if cached is None else "hit") if hit else "miss"
                metrics.ENRICHMENT_CACHE.labels(provider=self.name, result=result).inc()
                initial = False
            if hit:
                return cached, "ok"
            cooldown = await self._read_cooldown()
            if cooldown is not None:
                return None, cooldown
            # The owner must finish before its lease expires, even when the HTTP
            # timeout is configured above the store's default five-second lease.
            ttl_ms = max(1, math.ceil((deadline - loop.time()) * 1000)) + 1000
            lease = AsyncExitStack()
            try:
                acquired = await lease.enter_async_context(
                    self._store.lock(
                        keys.enrichment_lock_key("vt", ip), ttl_ms=ttl_ms, wait_timeout=0
                    )
                )
                if acquired:
                    # Another owner may have filled the cache between our read
                    # and SET NX. Reserve quota only after this second check.
                    hit, cached = await self._read_cache(ip)
                    if hit:
                        return cached, "ok"
                    cooldown = await self._read_cooldown()
                    if cooldown is not None:
                        return None, cooldown
                    return await self._request(ip, deadline)
            finally:
                # A timed-out or cancelled HTTP must not wait for an unresponsive
                # Redis during unlock. The lease's TTL is the recovery fallback.
                try:
                    async with asyncio.timeout_at(deadline):
                        await lease.aclose()
                except TimeoutError:
                    pass
            await asyncio.sleep(0.01)

    def _cooldown_key(self, reason: str) -> str:
        fingerprint = hashlib.sha256(self._api_key.encode()).hexdigest()
        return keys.enrichment_cooldown_key("vt", fingerprint, reason)

    async def _read_cooldown(self) -> LookupStatus | None:
        for reason in ("auth", "rate", "error"):
            raw = await self._store.get_value(self._cooldown_key(reason))
            if raw is None:
                continue
            try:
                marker = _Cooldown.model_validate_json(raw)
            except ValidationError:
                continue
            if await self._store.client.pttl(self._cooldown_key(reason)) > 0:
                self._skip(
                    {
                        "auth": "cooldown_auth",
                        "rate": "cooldown_rate_limit",
                        "error": "cooldown_error",
                    }[reason]
                )
                return marker.status
        return None

    async def _pause(
        self, reason: str, status: Literal["unauthorized", "quota", "unavailable"], ttl: float
    ) -> None:
        changed = await self._store.extend_cached_value(
            self._cooldown_key(reason), _Cooldown(status=status).model_dump_json(), ttl=ttl
        )
        if changed and self._audit is not None:
            self._audit.emit(
                "enrichment_cooldown_changed",
                "warning",
                {"provider": self.name, "reason": reason, "outcome": status, "seconds": ttl},
            )

    def _retry_after(self, value: str | None) -> float:
        delay = self._rate_limit_cooldown
        if value:
            try:
                if value.isascii() and value.isdecimal():
                    delay = float(value)
                else:
                    date = parsedate_to_datetime(value)
                    if date.tzinfo is None:
                        raise ValueError("Retry-After date requires timezone")
                    delay = date.timestamp() - self._clock()
            except (ValueError, TypeError, OverflowError):
                delay = self._rate_limit_cooldown
        return min(self._max_retry_after, max(1.0, delay))

    async def _request(
        self, ip: str, deadline: float
    ) -> tuple[VirusTotalReport | None, LookupStatus]:
        """Fetch and cache one result while holding the per-address lease."""
        if not await self._reserve():
            self._skip("quota")
            return None, "quota"

        try:
            # Leave part of the existing budget for persisting a timeout pause.
            remaining = deadline - asyncio.get_running_loop().time()
            request_budget = min(self._http_timeout, max(0.0, remaining * 0.8))
            response = await self._http_request(ip, request_budget)
        except (httpx.HTTPError, TimeoutError):
            await self._pause("error", "unavailable", self._error_cooldown)
            return None, "unavailable"

        if response.status_code == 429:
            # Reserved slot spent by somebody else sharing the key, or our own
            # counters drifted from the server's view. Either way: stop asking.
            await self._pause(
                "rate", "quota", self._retry_after(response.headers.get("Retry-After"))
            )
            return None, "quota"
        if response.status_code in (401, 403):
            # A wrong, revoked or disabled key. Retrying spends nothing useful:
            # every alert would fail the same way until somebody fixes the key.
            await self._pause("auth", "unauthorized", self._auth_cooldown)
            return None, "unauthorized"
        if response.status_code == 404:
            try:
                payload = response.json()
                not_found = (
                    isinstance(payload, dict)
                    and payload.get("error", {}).get("code") == "NotFoundError"
                )
            except (ValueError, AttributeError):
                not_found = False
            if not_found:
                await self._write_cache(ip, None, ttl=self._miss_cache_ttl)
                return None, "ok"
        if response.status_code != 200:
            await self._pause("error", "unavailable", self._error_cooldown)
            return None, "unavailable"

        try:
            payload = response.json()
            report = _parse(payload)
        except (ValueError, TypeError, KeyError, AttributeError):
            await self._pause("error", "unavailable", self._error_cooldown)
            return None, "unavailable"
        if report is None:
            await self._write_cache(ip, None, ttl=self._miss_cache_ttl)
            return None, "ok"
        await self._write_cache(ip, report, ttl=self._cache_ttl)
        return report, "ok"

    async def _http_request(self, ip: str, budget: float) -> httpx.Response:
        """Count only an actual HTTP attempt, independently of Redis persistence."""
        outcome = "cancelled"
        try:
            async with asyncio.timeout(budget):
                response = await self._client.get(
                    f"{VIRUSTOTAL_ENDPOINT}{ip}", headers={"x-apikey": self._api_key}
                )
            if response.status_code == 200:
                outcome = "ok"
            elif response.status_code == 404:
                outcome = "not_found"
            elif response.status_code in (401, 403):
                outcome = "unauthorized"
            elif response.status_code == 429:
                outcome = "quota"
            else:
                outcome = "http_error"
            return response
        except (httpx.TimeoutException, TimeoutError):
            outcome = "timeout"
            raise
        except httpx.HTTPError:
            outcome = "network_error"
            raise
        finally:
            metrics.ENRICHMENT_REQUESTS.labels(provider=self.name, outcome=outcome).inc()

    # --- Quota --------------------------------------------------------------

    async def _reserve(self) -> bool:
        """Take one slot in the minute, day and month windows."""
        windows = [(key, limit, ttl) for key, limit, ttl, _ in self._quota_windows()]
        return await self._store.reserve_quota(windows)

    async def exhausted_window(self) -> str | None:
        """Name the free-tier window that is full, or None when none is.

        Only called after a refusal, so the three reads never touch the hot path.
        Knowing *which* window is spent is the difference between "wait a minute"
        and "the daily budget is gone until midnight".
        """
        for key, limit, _ttl, name in self._quota_windows():
            raw = await self._store.get_value(key)
            try:
                used = int(raw) if raw is not None else 0
            except ValueError:  # pragma: no cover - the counter is written by this client
                used = 0
            if used >= limit:
                return name
        return None

    def _quota_windows(self) -> list[tuple[str, int, int, str]]:
        """`(key, limit, ttl_ms, name)` for the minute, the day and the month."""
        now = datetime.fromtimestamp(self._clock(), tz=UTC)
        limits = self._limits
        return [
            (
                keys.quota_key("virustotal", "minute", now.strftime("%Y%m%d%H%M")),
                limits.per_minute,
                60_000,
                "minute",
            ),
            (
                keys.quota_key("virustotal", "day", now.strftime("%Y%m%d")),
                limits.per_day,
                24 * 3600 * 1000,
                "day",
            ),
            (
                keys.quota_key("virustotal", "month", now.strftime("%Y%m")),
                limits.per_month,
                int(_MONTH_SECONDS * 1000),
                "month",
            ),
        ]

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
        if ttl <= 0:
            return
        payload = json.dumps(report.model_dump() if report is not None else None)
        await self._store.set_with_ttl(keys.enrichment_cache_key("vt", ip), payload, ttl=ttl)


def _parse(payload: object) -> VirusTotalReport | None:
    """Turn a VirusTotal IP object into a report, or None when it has no data."""
    if not isinstance(payload, dict):
        raise ValueError("invalid IP object")
    data = payload.get("data")
    if not isinstance(data, dict):
        raise ValueError("invalid IP data")
    attributes = data.get("attributes")
    if not isinstance(attributes, dict):
        raise ValueError("invalid IP attributes")
    stats = attributes.get("last_analysis_stats")
    if stats is None:
        return None
    if not isinstance(stats, dict):
        raise ValueError("invalid analysis stats")

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


__all__ = ["LookupStatus", "QuotaLimits", "VirusTotalClient"]
