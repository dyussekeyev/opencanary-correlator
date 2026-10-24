"""The Redis key layout is part of the console compatibility contract."""

from __future__ import annotations

import hashlib

from opencanary_correlator.storage.keys import (
    dedup_key,
    device_hash,
    device_key,
    host_scan_key,
    incident_key,
    incident_lock_key,
    incident_prefix,
    network_scan_key,
)


def test_incident_key_matches_legacy_layout() -> None:
    assert (
        incident_key("ftp.login_attempt", "10.0.0.5", 1418997029)
        == "incident:ftplogin:10.0.0.5:1418997029"
    )
    assert (
        incident_prefix("scans.network_portscan", "10.0.0.5") == "incident:networkportscan:10.0.0.5"
    )


def test_device_hash_matches_truncated_sha256() -> None:
    expected = hashlib.sha256(b"23456").hexdigest()[:12]

    assert device_hash("23456") == expected
    assert len(device_hash("canary-1")) == 12
    assert device_key("23456") == f"device:{expected}"


def test_scan_keys_match_legacy_layout() -> None:
    assert host_scan_key("10.0.0.5", "10.0.0.2") == "scan:host:10.0.0.5:10.0.0.2"
    assert network_scan_key("10.0.0.5", 22) == "scan:network:10.0.0.5:22:targets"


def test_lock_and_dedup_keys_are_namespaced() -> None:
    assert incident_lock_key("ftp.login_attempt", "10.0.0.5") == (
        "incident-lock:ftp.login_attempt:10.0.0.5"
    )
    assert dedup_key("abc") == "dedup:abc"
