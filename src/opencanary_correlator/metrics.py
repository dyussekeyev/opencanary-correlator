"""Prometheus metrics exposed on the health listener.

The counters are process-local: every correlator replica is scraped separately,
which is the expected Prometheus model for a horizontally scaled service. Labels
are deliberately low-cardinality (channel/rule/reason), never incident keys,
source addresses or payload contents.

Metrics are registered on the default ``prometheus_client`` registry so the
standard library collectors (process, GC, Python) are exported as well.
"""

from __future__ import annotations

from platform import python_version

from prometheus_client import Counter, Gauge, Info, generate_latest

from opencanary_correlator import __version__

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"

EVENTS_TOTAL = Counter(
    "opencanary_events_total",
    "Events handled by the correlator, by result",
    ["result"],
)
EVENTS_DROPPED = Counter(
    "opencanary_events_dropped_total",
    "Events discarded before correlation, by reason",
    ["reason"],
)
EVENTS_IGNORED = Counter(
    "opencanary_events_ignored_total",
    "Valid events a rule deliberately did not correlate, by reason",
    ["reason"],
)
EVENT_QUEUE_DEPTH = Gauge(
    "opencanary_event_queue_depth",
    "Events waiting in the bounded receiver queue",
)
ACTIVE_CONNECTIONS = Gauge(
    "opencanary_active_connections",
    "Currently open receiver connections",
    ["receiver"],
)
CONNECTION_REJECTIONS = Counter(
    "opencanary_connection_rejections_total",
    "Connections rejected before any payload was processed",
    ["receiver", "reason"],
)
RULE_FAILURES = Counter(
    "opencanary_rule_failures_total",
    "Rule evaluation failures isolated by the engine",
    ["rule"],
)
OUTBOX_PENDING = Gauge(
    "opencanary_outbox_pending",
    "Alert deliveries waiting for a retry",
)
OUTBOX_DELIVERED = Counter(
    "opencanary_outbox_delivered_total",
    "Alert deliveries settled as accepted",
    ["channel"],
)
OUTBOX_RETRIED = Counter(
    "opencanary_outbox_retried_total",
    "Alert deliveries rescheduled for another attempt",
    ["channel"],
)
OUTBOX_DEAD = Counter(
    "opencanary_outbox_dead_total",
    "Alert deliveries buried in the dead letter list",
    ["channel"],
)
ALERTS_TOTAL = Counter(
    "opencanary_alerts_total",
    "Alert delivery attempts, by dispatcher and outcome",
    ["dispatcher", "status"],
)
ALERTS_BUDGET = Counter(
    "opencanary_alerts_budget_total",
    "Notifications the alert budget allowed or withheld",
    ["result"],
)
BUILD_INFO = Info(
    "opencanary_build",
    "Static build information for the running correlator",
)
BUILD_INFO.info({"version": __version__, "python": python_version()})


def render() -> bytes:
    """Render the default registry in Prometheus text exposition format."""
    return generate_latest()


__all__ = ["CONTENT_TYPE", "render"]
