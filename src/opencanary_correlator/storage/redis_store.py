"""Async Redis access layer.

All correlation state lives here so replicas stay stateless. Multi-step writes
(window updates) go through transactional pipelines, incident persistence and
the lock release run as Lua scripts (one atomic round trip each), and incident
creation is serialised with a short-lived distributed lock, because a lost
update would mean a duplicate alert. Incident lookup uses a per-host pointer so
it does not have to walk the whole ``incidents`` index on every event, and the
fallback scan is capped by `OCC_INCIDENT_LOOKUP_SCAN_LIMIT` so the cost of an
event cannot grow with the size of that index.

The class is assembled from one mixin per concern, so a reader looking for
deduplication, a quota or the incident path finds one small module instead of
searching 400 lines:

===================  ==========================================================
:mod:`_base`         the client, its scripts, text normalisation, plain keys
:mod:`_dedup`        first-writer-wins fingerprints
:mod:`_windows`      set, ZSET and counter windows with a fixed expiry
:mod:`_quota`        atomic multi-window reservations
:mod:`_cache`        string values (the enrichment cache)
:mod:`_console`      the bounded legacy console journal
:mod:`_incidents`    incident hash, index pointer and bounded lookup scan
:mod:`_budget`       the per-node notification budget and its window summaries
:mod:`_outbox`       pending alert deliveries, retries and the dead letter list
:mod:`_service`      suppression slots for service messages
:mod:`_stats`        replica heartbeats and the incident/window reads
:mod:`_locks`        the short-lived distributed lock
===================  ==========================================================

The client targets one logical Redis server. Redis Cluster is not supported:
:meth:`save_incident` writes an ``incident:*`` hash, the ``incidents`` ZSET and
the host pointer, which are different Cluster slots (``CROSSSLOT``).
Hash-tagging them would change the legacy key layout, so use a primary/replica
or failover endpoint.
"""

from __future__ import annotations

from opencanary_correlator.storage._base import IncidentLookup, _StoreBase
from opencanary_correlator.storage._budget import _BudgetMixin
from opencanary_correlator.storage._cache import _CacheMixin
from opencanary_correlator.storage._console import _ConsoleMixin
from opencanary_correlator.storage._dedup import _DedupMixin
from opencanary_correlator.storage._incidents import _IncidentsMixin
from opencanary_correlator.storage._locks import (
    DEFAULT_LOCK_TTL_MS,
    DEFAULT_LOCK_WAIT_SECONDS,
    LOCK_RETRY_INTERVAL_SECONDS,
    _LockMixin,
)
from opencanary_correlator.storage._outbox import _OutboxMixin
from opencanary_correlator.storage._quota import _QuotaMixin
from opencanary_correlator.storage._service import _ServiceMixin
from opencanary_correlator.storage._stats import _StatsMixin
from opencanary_correlator.storage._windows import _WindowsMixin


class RedisStore(
    _DedupMixin,
    _WindowsMixin,
    _QuotaMixin,
    _CacheMixin,
    _ConsoleMixin,
    _IncidentsMixin,
    _OutboxMixin,
    _ServiceMixin,
    _StatsMixin,
    _BudgetMixin,
    _LockMixin,
    _StoreBase,
):
    """Typed wrapper around `redis.asyncio.Redis` used by the correlator.

    Every method comes from one of the mixins listed in the module docstring;
    the class itself only fixes the order in which they are combined.
    """


__all__ = [
    "DEFAULT_LOCK_TTL_MS",
    "DEFAULT_LOCK_WAIT_SECONDS",
    "LOCK_RETRY_INTERVAL_SECONDS",
    "IncidentLookup",
    "RedisStore",
]
