"""One delivery attempt, shared by the inline path and the outbox worker.

The engine tries a channel immediately after the incident is written; the worker
retries from the outbox. Both must report a failure the same way — an audit
record, a metric and a reason the outbox can store — so the timing, the timeout
and the classification live here instead of being written twice.
"""

from __future__ import annotations

import asyncio
import time

from opencanary_correlator import metrics
from opencanary_correlator.audit import AuditLogger
from opencanary_correlator.connectors.base import BaseDispatcher, DispatchResult, IncidentLike


def _elapsed_ms(started: float) -> float:
    """Milliseconds since `started`, rounded for the audit line."""
    return round((time.perf_counter() - started) * 1000, 1)


async def deliver(
    dispatcher: BaseDispatcher,
    incident: IncidentLike,
    *,
    audit: AuditLogger,
    deadline: float,
) -> DispatchResult | None:
    """Deliver one incident, returning the outcome or None on timeout/exception.

    Never raises: a channel that is down must not cost the incident, and the
    caller decides what to do with the failure (the outbox reschedules it).
    """
    started = time.perf_counter()

    try:
        result = await asyncio.wait_for(dispatcher.dispatch(incident), timeout=float(deadline))
    except TimeoutError:
        metrics.ALERTS_TOTAL.labels(dispatcher=dispatcher.name, status="timeout").inc()
        audit.emit(
            "alert_dispatch",
            "error",
            {
                "dispatcher": dispatcher.name,
                "incident": incident.key,
                "reason": "timeout",
                "duration_ms": _elapsed_ms(started),
            },
        )
        return None
    except Exception as exc:
        metrics.ALERTS_TOTAL.labels(dispatcher=dispatcher.name, status="exception").inc()
        audit.emit(
            "alert_dispatch",
            "error",
            {
                "dispatcher": dispatcher.name,
                "incident": incident.key,
                "error_type": type(exc).__name__,
                "duration_ms": _elapsed_ms(started),
            },
        )
        return None

    metrics.ALERTS_TOTAL.labels(dispatcher=dispatcher.name, status=result.status).inc()
    audit.emit(
        "alert_dispatch",
        "success" if result.status == "success" else "error",
        {
            "dispatcher": dispatcher.name,
            "incident": incident.key,
            "status": result.status,
            "duration_ms": _elapsed_ms(started),
        },
    )
    return result


__all__ = ["deliver"]
