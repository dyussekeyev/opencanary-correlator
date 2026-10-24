"""Redis key builders matching the Python 2 implementation exactly.

The legacy console reads these keys directly, so the layout is part of the
compatibility contract even though honeypot nodes never touch Redis.
"""

from __future__ import annotations

import hashlib

from opencanary_correlator.constants import (
    INCIDENT_KEY_PREFIX,
    KEY_DEVICE,
    KEY_TRACK_HOST_PORT_SCAN,
    KEY_TRACK_NETWORK_PORT_SCAN,
)

DEDUP_KEY_PREFIX = "dedup:"
INCIDENT_LOCK_PREFIX = "incident-lock:"


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


def host_scan_key(src_host: str, dst_host: str) -> str:
    """Legacy key tracking distinct destination ports per source/target pair."""
    return f"{KEY_TRACK_HOST_PORT_SCAN}{src_host}:{dst_host}"


def network_scan_key(src_host: str, dst_port: int) -> str:
    """Legacy key tracking distinct canary targets per source host and port."""
    return f"{KEY_TRACK_NETWORK_PORT_SCAN}{src_host}:{dst_port}:targets"


def dedup_key(fingerprint: str) -> str:
    """Key used to remember an already-processed event fingerprint."""
    return f"{DEDUP_KEY_PREFIX}{fingerprint}"


__all__ = [
    "DEDUP_KEY_PREFIX",
    "INCIDENT_LOCK_PREFIX",
    "dedup_key",
    "device_hash",
    "device_key",
    "host_scan_key",
    "incident_key",
    "incident_lock_key",
    "incident_prefix",
    "network_scan_key",
]
