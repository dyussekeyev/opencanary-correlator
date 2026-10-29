"""The daily digest: what the correlator did in the last 24 hours.

The window is trailing — `now - 24 h` to `now` — rather than midnight to midnight,
so a run is never partial just because a replica restarted at 23:50.

Exactly-once is enforced in two layers: a short lock elects the replica producing
the digest, and a `SET NX` marker for the day (`digest:sent:<date>`) makes a
second attempt a no-op even if the lock expired between two scheduling ticks. The
marker is written after the message is accepted, so a crash mid-send can replay
the digest once; writing it before would lose the day instead.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from typing import Final

from opencanary_correlator.audit import AuditLogger
from opencanary_correlator.config import Settings
from opencanary_correlator.core.service_messages import (
    ServiceKind,
    ServiceMessage,
    ServiceNotifier,
)
from opencanary_correlator.core.stats import DigestData, collect_digest
from opencanary_correlator.storage import keys
from opencanary_correlator.storage.redis_store import RedisStore

#: A digest that needs longer than this to render and send is pathological; the
#: lock is released by its TTL either way.
DIGEST_LOCK_TTL_MS: Final[int] = 5 * 60 * 1000
#: The election lock needs no waiting: a replica that loses does nothing.
DIGEST_LOCK_WAIT_SECONDS: Final[float] = 0.0
#: Longest single sleep in the scheduler loop, so a clock jump or a changed time
#: is picked up within a minute instead of a day.
MAX_SLEEP: Final[float] = 60.0
#: The day a digest covers is remembered for a week: long enough to explain a
#: missed message, short enough not to accumulate.
SENT_MARKER_TTL: Final[float] = 7 * 24 * 3600.0


def next_run(now: float, at: str) -> float:
    """Epoch of the next `HH:MM` UTC strictly after `now`."""
    hour, minute = (int(part) for part in at.split(":"))
    moment = datetime.fromtimestamp(now, tz=UTC)
    target = moment.replace(hour=hour, minute=minute, second=0, microsecond=0)
    epoch = target.timestamp()
    if epoch <= now:
        epoch = (target + timedelta(days=1)).timestamp()
    return epoch


def _utc(epoch: float) -> str:
    """Render an epoch as a UTC timestamp, the way alerts do."""
    try:
        return datetime.fromtimestamp(epoch, tz=UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OverflowError, OSError, ValueError):  # pragma: no cover - absurd clock
        return "unknown"


def render_digest(data: DigestData) -> tuple[str, tuple[str, ...]]:
    """Render the digest as a title and its rows, for any channel's notice path.

    Plain data only: counts and attacker addresses, no keys, no URLs. The lines
    are the same for every channel, which is what lets one message go out through
    Telegram, Slack, Discord and mail without per-channel templates.
    """
    events = data.events
    alerts = data.alerts
    lines = [
        f"🕒 Window: {_utc(data.start)} - {_utc(data.end)}",
        f"🖥 Replicas: {data.replicas}",
        "",
        f"📥 Events: {events.get('accepted', 0)} accepted, "
        f"{events.get('rejected', 0)} rejected, {events.get('dropped', 0)} dropped",
        f"♻️ Deduplicated: {events.get('deduplicated', 0)} • Unrouted: {events.get('unrouted', 0)}",
        f"🚨 Incidents: {data.incidents}",
        f"📤 Alerts: {alerts.get('success', 0)} delivered, "
        f"{alerts.get('error', 0)} failed, {alerts.get('timeout', 0)} timed out",
    ]
    if data.rule_failures:
        lines.append(f"⚠️ Rule failures: {data.rule_failures}")
    if data.quota_day or data.quota_month:
        lines.append(
            f"🦠 VirusTotal lookups: {data.quota_day} today, {data.quota_month} this month"
        )
    if data.top_sources:
        lines.append("")
        lines.append("🎯 Busiest sources:")
        lines.extend(f"• {host}: {count}" for host, count in data.top_sources)
    day = datetime.fromtimestamp(data.end, tz=UTC).strftime("%Y-%m-%d")
    return f"daily digest {day}", tuple(lines)


class DigestScheduler:
    """Send the digest once a day, from one replica."""

    name: Final[str] = "digest"

    def __init__(
        self,
        store: RedisStore,
        notifier: ServiceNotifier,
        settings: Settings,
        audit: AuditLogger,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._store = store
        self._notifier = notifier
        self._settings = settings
        self._audit = audit
        self._clock = clock
        self._task: asyncio.Task[None] | None = None
        self._stop = asyncio.Event()

    # --- One run ------------------------------------------------------------

    async def run_once(self, now: float | None = None) -> bool:
        """Produce the digest for the window ending now, at most once per day."""
        moment = float(self._clock() if now is None else now)
        day = datetime.fromtimestamp(moment, tz=UTC).strftime("%Y-%m-%d")
        marker = keys.digest_sent_key(day)
        if await self._store.exists(marker):
            return False

        async with self._store.lock(
            keys.digest_lock_key(day),
            ttl_ms=DIGEST_LOCK_TTL_MS,
            wait_timeout=DIGEST_LOCK_WAIT_SECONDS,
        ) as acquired:
            if not acquired:
                return False
            if await self._store.exists(marker):
                # Another replica finished between the check and the lock.
                return False

            data = await collect_digest(
                self._store, now=moment, top_sources=self._settings.digest_top_sources
            )
            title, lines = render_digest(data)
            message = ServiceMessage(
                kind=ServiceKind.DIGEST_DAILY, title=title, lines=lines, subject=day
            )
            sent = await self._notifier.send(message, channels=self._channels())
            if sent:
                await self._store.set_if_absent(marker, "1", ttl=SENT_MARKER_TTL)
            self._audit.emit(
                "digest_sent",
                "success" if sent else "error",
                {
                    "day": day,
                    "incidents": data.incidents,
                    "replicas": data.replicas,
                    "events": data.total_events,
                },
            )
            return sent

    def _channels(self) -> Sequence[str]:
        """Where the digest goes: its own list, else the service-message routing."""
        return tuple(self._settings.digest_channels or self._settings.service_channels)

    # --- Scheduling ---------------------------------------------------------

    async def start(self) -> None:
        """Start the loop that waits for `OCC_DIGEST_TIME` each day."""
        if self._task is None:
            self._task = asyncio.create_task(self._loop(), name="digest-scheduler")

    async def stop(self) -> None:
        """Wake the loop, cancel it and wait for it to unwind."""
        task, self._task = self._task, None
        self._stop.set()
        if task is None:
            return
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

    async def _loop(self) -> None:
        while not self._stop.is_set():
            target = next_run(float(self._clock()), self._settings.digest_time)
            delay = max(0.0, target - float(self._clock()))
            if await self._wait(min(delay, MAX_SLEEP)):
                return
            if float(self._clock()) < target:
                continue
            try:
                await self.run_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # a digest bug must not kill the process
                self._audit.emit("digest_failed", "error", {"error_type": type(exc).__name__})

    async def _wait(self, delay: float) -> bool:
        """Sleep up to `delay` seconds; return True when a stop was requested."""
        if delay <= 0:
            return self._stop.is_set()
        try:
            await asyncio.wait_for(self._stop.wait(), timeout=delay)
        except TimeoutError:
            return False
        return True


__all__ = [
    "DIGEST_LOCK_TTL_MS",
    "MAX_SLEEP",
    "SENT_MARKER_TTL",
    "DigestScheduler",
    "next_run",
    "render_digest",
]
