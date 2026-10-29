"""The alert budget: a ration on notifications, not on incidents.

A burst of distinct incidents — one noisy subnet probing a hundred addresses in
a minute — can bury the alert an operator needed to see. The budget keeps every
incident: it is stored, indexed and visible in the console exactly as before.
What it withholds is the *notification*, and only while the window's count is
exhausted.

Two properties make that acceptable rather than silent data loss:

* a withheld alert is an audit record (``alert_suppressed``) carrying the source
  node and the incident key, so the trail is complete;
* the window's refusals are accumulated in Redis and delivered as one summary
  when the window closes (``alert_summary``), so the ration cannot hide itself.

The counters live in Redis and are reserved by one Lua script, so two replicas
share a single budget: scaling out does not multiply the ration.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final

from opencanary_correlator import metrics
from opencanary_correlator.audit import AuditLogger
from opencanary_correlator.config import Settings
from opencanary_correlator.connectors.base import BaseDispatcher
from opencanary_correlator.redaction import sanitize_text
from opencanary_correlator.storage.redis_store import RedisStore

logger = logging.getLogger(__name__)

#: Line separator used by every rendered message (see `alert_text.CRLF`).
CRLF: Final[str] = "\r\n"
#: Sources listed in one summary before the rest are collapsed into a count.
_MAX_SUMMARY_SOURCES: Final[int] = 10
#: Summaries a worker takes per iteration.
SUMMARY_BATCH: Final[int] = 20


@dataclass(frozen=True, slots=True)
class BudgetSummary:
    """What one closed budget window withheld."""

    start: int
    end: int
    counts: Mapping[str, int]

    @property
    def suppressed(self) -> int:
        """Total notifications withheld in the window."""
        return sum(self.counts.values())

    @property
    def sources(self) -> int:
        """Distinct canaries whose alerts were withheld."""
        return len(self.counts)


def _utc(epoch: int) -> str:
    """Render an epoch as a UTC timestamp, the way alerts do."""
    try:
        return datetime.fromtimestamp(epoch, tz=UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OverflowError, OSError, ValueError):  # pragma: no cover - absurd clock
        return "unknown"


def render_budget_summary(summary: BudgetSummary, *, limit: int = _MAX_SUMMARY_SOURCES) -> str:
    """Render the withheld-notification summary as one plain-text message.

    Plain text on purpose: this goes out through every channel's notice path,
    which does not run the channel's markup escaping, so a node id from network
    input must be flattened here instead (`sanitize_text`).
    """
    total = summary.suppressed
    lines = [
        "🛡 OpenCanary: alert budget",
        "",
        f"🔕 Suppressed: {total} alerts",
        f"🕒 Window: {_utc(summary.start)} - {_utc(summary.end)}",
        f"🖥 Instances: {summary.sources}",
    ]
    ranked = sorted(summary.counts.items(), key=lambda item: (-item[1], item[0]))
    if ranked:
        lines.append("")
        for node_id, count in ranked[:limit]:
            name = sanitize_text(node_id, limit=120, collapse=True) or "unknown"
            lines.append(f"• {name}: {count}")
        hidden = len(ranked) - len(ranked[:limit])
        if hidden > 0:
            lines.append(f"• (+{hidden} more instances)")
    return CRLF.join(lines)


class AlertBudget:
    """Reserve notifications, and summarise what the windows withheld."""

    name: Final[str] = "alert_budget"

    def __init__(
        self,
        store: RedisStore,
        dispatchers: Sequence[BaseDispatcher],
        settings: Settings,
        audit: AuditLogger,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._store = store
        self._dispatchers = list(dispatchers)
        self._settings = settings
        self._audit = audit
        self._clock = clock
        self._task: asyncio.Task[None] | None = None

    # --- Reservation --------------------------------------------------------

    def window_bounds(self, now: float | None = None) -> tuple[int, int]:
        """Fixed window containing `now`, as `(start, end)` epochs."""
        moment = float(self._clock() if now is None else now)
        window = float(self._settings.alert_budget_window)
        start = int(moment - moment % window)
        return start, int(start + window)

    async def allow(self, node_id: str) -> bool:
        """Return True when this notification fits in the budget.

        False means "do not notify": the incident itself is already stored (the
        caller stores it either way), and the refusal is counted for the
        window's summary by the same atomic reservation.
        """
        start, end = self.window_bounds()
        allowed = await self._store.reserve_alert_slot(
            node_id=node_id,
            stamp=start,
            per_node=self._settings.alert_budget_per_node,
            global_limit=self._settings.alert_budget_global,
            window=float(self._settings.alert_budget_window),
            summary_due=float(end),
        )
        metrics.ALERTS_BUDGET.labels(result="allowed" if allowed else "suppressed").inc()
        return allowed

    # --- Summary worker -----------------------------------------------------

    async def start(self) -> None:
        """Start the loop that delivers closed-window summaries."""
        if self._task is None:
            self._task = asyncio.create_task(self._loop(), name="alert-budget")

    async def stop(self) -> None:
        """Cancel the summary loop and wait for it to unwind."""
        task, self._task = self._task, None
        if task is None:
            return
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

    async def run_once(self) -> int:
        """Deliver every summary whose window has closed, returning how many."""
        now = float(self._clock())
        due = await self._store.due_budget_summaries(now=now, limit=SUMMARY_BATCH)
        delivered = 0
        for summary_key in due:
            counts = await self._store.take_budget_summary(summary_key)
            if not counts:
                continue
            summary = self._summary(summary_key, counts)
            self._audit.emit(
                "alert_summary",
                "info",
                {
                    "window_start": summary.start,
                    "window_end": summary.end,
                    "suppressed": summary.suppressed,
                    "sources": summary.sources,
                },
            )
            if await self._announce(summary):
                delivered += 1
        return delivered

    async def _loop(self) -> None:
        while True:
            try:
                await self.run_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # a summary bug must not kill the process
                self._audit.emit(
                    "alert_summary_failed",
                    "error",
                    {"error_type": type(exc).__name__},
                )
            await asyncio.sleep(self._settings.alert_budget_poll_interval)

    def _summary(self, summary_key: str, counts: Mapping[str, int]) -> BudgetSummary:
        """Rebuild the window bounds from the summary key that names them.

        The index member is the summary hash key, whose stamp is the window
        start, so the worker cannot report a window other than the one it took.
        """
        try:
            start = int(summary_key.rsplit(":", 1)[-1])
        except ValueError:  # pragma: no cover - the key is written by this module
            start = 0
        window = int(self._settings.alert_budget_window)
        return BudgetSummary(start=start, end=start + window, counts=dict(counts))

    async def _announce(self, summary: BudgetSummary) -> bool:
        """Send the summary to every channel that can carry a notice."""
        text = render_budget_summary(summary)
        results = await asyncio.gather(
            *(self._announce_one(dispatcher, text) for dispatcher in self._dispatchers)
        )
        return any(results)

    async def _announce_one(self, dispatcher: BaseDispatcher, text: str) -> bool:
        """One channel, bounded by its own timeout, never raising."""
        try:
            result = await asyncio.wait_for(
                dispatcher.announce(text),
                timeout=float(self._settings.dispatch_timeout),
            )
        except Exception as exc:
            self._audit.emit(
                "alert_summary",
                "error",
                {"dispatcher": dispatcher.name, "error_type": type(exc).__name__},
            )
            return False
        status = result.status
        self._audit.emit(
            "alert_summary",
            "success" if status == "success" else "error",
            {"dispatcher": dispatcher.name, "status": status, "detail": result.detail},
        )
        return status == "success"


__all__ = [
    "CRLF",
    "SUMMARY_BATCH",
    "AlertBudget",
    "BudgetSummary",
    "render_budget_summary",
]
