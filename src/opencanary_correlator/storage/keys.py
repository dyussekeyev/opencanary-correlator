"""Redis key builders matching the Python 2 implementation exactly.

The legacy console reads these keys directly, so the layout is part of the
compatibility contract even though honeypot nodes never touch Redis.
"""

from __future__ import annotations

import hashlib

from opencanary_correlator.constants import (
    INCIDENT_KEY_PREFIX,
    KEY_CONSOLE_SETTING_PREFIX,
    KEY_DEVICE,
    KEY_TRACK_HOST_PORT_SCAN,
    KEY_TRACK_NETWORK_PORT_SCAN,
)

DEDUP_KEY_PREFIX = "dedup:"
INCIDENT_LOCK_PREFIX = "incident-lock:"
INCIDENT_LATEST_PREFIX = "incident-latest:"
ENRICHMENT_PREFIX = "enrichment:"
QUOTA_PREFIX = "quota:"

#: ZSET of pending alert deliveries, scored by their next attempt.
OUTBOX_INDEX = "outbox:alerts"
OUTBOX_ENTRY_PREFIX = "outbox:alert:"
#: Deliveries that exhausted their attempts, kept for an operator to inspect.
OUTBOX_DEAD = "outbox:dead"
DELIVERED_PREFIX = "outbox:delivered:"

#: ZSET of alert-budget summaries, scored by the end of their window.
BUDGET_SUMMARIES = "budget:summaries"

#: Lock that elects the replica running one health-watch interval.
WATCH_LOCK_PREFIX = "health-watch:"


def device_hash(node_id: str) -> str:
    """Return the legacy device hash: a truncated SHA-256 of the node id.

    The legacy code used ``nacl.hash.sha256(..., RawEncoder)[:12].hex()``; this
    is the same digest without the PyNaCl dependency.
    """
    return hashlib.sha256(node_id.encode("utf-8")).hexdigest()[:12]


def device_key(node_id: str) -> str:
    """Key of the device hash for `node_id`."""
    return f"{KEY_DEVICE}{device_hash(node_id)}"


def incident_prefix(incident_name: str, src_host: str) -> str:
    """Prefix shared by every incident of `incident_name` from `src_host`."""
    return f"{INCIDENT_KEY_PREFIX[incident_name]}{src_host}"


def incident_key(incident_name: str, src_host: str, timestamp: int | float | str) -> str:
    """Full incident hash key, matching the legacy ``prefix + src_host + ':' + ts``."""
    return f"{incident_prefix(incident_name, src_host)}:{timestamp}"


def incident_lock_key(incident_name: str, src_host: str) -> str:
    """Distributed lock guarding incident creation for one source host."""
    return f"{INCIDENT_LOCK_PREFIX}{incident_name}:{src_host}"


def incident_latest_key(incident_name: str, src_host: str) -> str:
    """Pointer to the newest incident of one type for one source host.

    This is an internal index only: the console never reads it, and a missing
    pointer simply falls back to scanning the legacy ``incidents`` ZSET.
    """
    return f"{INCIDENT_LATEST_PREFIX}{incident_name}:{src_host}"


def host_scan_key(src_host: str, dst_host: str) -> str:
    """Legacy key tracking distinct destination ports per source/target pair."""
    return f"{KEY_TRACK_HOST_PORT_SCAN}{src_host}:{dst_host}"


def network_scan_key(src_host: str, dst_port: int) -> str:
    """Legacy key tracking distinct canary targets per source host and port."""
    return f"{KEY_TRACK_NETWORK_PORT_SCAN}{src_host}:{dst_port}:targets"


def dedup_key(fingerprint: str) -> str:
    """Key used to remember an already-processed event fingerprint."""
    return f"{DEDUP_KEY_PREFIX}{fingerprint}"


def enrichment_cache_key(source: str, value: str) -> str:
    """Key holding one cached enrichment result.

    `source` names the provider (`vt`) and `value` the looked-up address. An IP
    address is public data and is not a credential, so it is used verbatim; a
    hashed key would make an operator's `redis-cli` debugging needlessly hard.
    """
    return f"{ENRICHMENT_PREFIX}{source}:{value}"


def quota_key(provider: str, window: str, stamp: str) -> str:
    """Counter for one provider quota window.

    The window stamp is part of the key (`quota:virustotal:day:20261028`), so a
    window that has rolled over starts at zero without any reset logic and a
    stale key simply expires. The provider is part of the key, not the prefix,
    so a second provider needs no new constant.
    """
    return f"{QUOTA_PREFIX}{provider}:{window}:{stamp}"


def budget_node_key(stamp: int, node_id: str) -> str:
    """Notifications counted for one canary inside one budget window.

    A fixed window is part of the key, so a rollover starts at zero without any
    reset logic and the expired key simply disappears.
    """
    return f"budget:node:{stamp}:{node_id}"


def budget_global_key(stamp: int) -> str:
    """Notifications counted for every canary together inside one window."""
    return f"budget:global:{stamp}"


def budget_summary_key(stamp: int) -> str:
    """What one window withheld, by source node."""
    return f"budget:suppressed:{stamp}"


def outbox_entry_id(incident_key: str, channel: str) -> str:
    """Deterministic id of one delivery.

    A retry is the same entry, not a new one, which is what makes the outbox
    at-least-once instead of at-least-once-plus-duplicates.
    """
    return f"{incident_key}#{channel}"


def outbox_alert_key(entry_id: str) -> str:
    """Hash holding one pending delivery."""
    return f"{OUTBOX_ENTRY_PREFIX}{entry_id}"


def delivered_key(entry_id: str) -> str:
    """Marker proving one delivery already reached its channel."""
    return f"{DELIVERED_PREFIX}{entry_id}"


def console_setting_key(setting: str) -> str:
    """Key of one console setting, as the legacy console reads it."""
    return f"{KEY_CONSOLE_SETTING_PREFIX}{setting}"


def service_subject_hash(subject: str) -> str:
    """Stable, short id of a service-message subject.

    The subject can be a node id taken from the wire or a filesystem path, so it
    is hashed rather than embedded: a key built from arbitrary input would let a
    canary create keys of any length, and a path in a Redis key is one more place
    it leaks.
    """
    return hashlib.sha256(subject.encode("utf-8")).hexdigest()[:16]


def service_message_keys(kind: str, subject: str) -> tuple[str, str]:
    """Suppression slot and repeat counter for one `(kind, subject)` pair."""
    suffix = f"{kind}:{service_subject_hash(subject)}"
    return f"service:mute:{suffix}", f"service:repeat:{suffix}"


#: Prefix of the per-replica heartbeat hash. One key per running process, with a
#: TTL, so the number of live replicas is the number of unexpired keys.
STATS_INSTANCE_PREFIX = "stats:instance:"
#: Marker proving one day's digest was already produced.
DIGEST_SENT_PREFIX = "digest:sent:"
#: Lock serialising the digest across replicas.
DIGEST_LOCK_PREFIX = "digest:lock:"


def stats_instance_key(instance_id: str) -> str:
    """Heartbeat hash of one replica."""
    return f"{STATS_INSTANCE_PREFIX}{instance_id}"


def digest_sent_key(day: str) -> str:
    """Marker for the digest of one UTC day (`YYYY-MM-DD`)."""
    return f"{DIGEST_SENT_PREFIX}{day}"


def digest_lock_key(day: str) -> str:
    """Lock that elects the replica producing one day's digest."""
    return f"{DIGEST_LOCK_PREFIX}{day}"


def watch_lock_key() -> str:
    """Lock that elects the replica running one health-watch interval."""
    return f"{WATCH_LOCK_PREFIX}check"


__all__ = [
    "BUDGET_SUMMARIES",
    "DEDUP_KEY_PREFIX",
    "DELIVERED_PREFIX",
    "DIGEST_LOCK_PREFIX",
    "DIGEST_SENT_PREFIX",
    "ENRICHMENT_PREFIX",
    "INCIDENT_LATEST_PREFIX",
    "INCIDENT_LOCK_PREFIX",
    "OUTBOX_DEAD",
    "OUTBOX_ENTRY_PREFIX",
    "OUTBOX_INDEX",
    "QUOTA_PREFIX",
    "STATS_INSTANCE_PREFIX",
    "WATCH_LOCK_PREFIX",
    "budget_global_key",
    "budget_node_key",
    "budget_summary_key",
    "console_setting_key",
    "dedup_key",
    "delivered_key",
    "device_hash",
    "device_key",
    "digest_lock_key",
    "digest_sent_key",
    "enrichment_cache_key",
    "host_scan_key",
    "incident_key",
    "incident_latest_key",
    "incident_lock_key",
    "incident_prefix",
    "network_scan_key",
    "outbox_alert_key",
    "outbox_entry_id",
    "quota_key",
    "service_message_keys",
    "service_subject_hash",
    "stats_instance_key",
    "watch_lock_key",
]
