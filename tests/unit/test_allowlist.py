"""Unit tests for the receiver source allowlist."""

from __future__ import annotations

import pytest

from opencanary_correlator.connectors.receivers._allowlist import (
    is_peer_allowed,
    parse_allowed_networks,
)


def test_empty_list_allows_every_peer() -> None:
    networks = parse_allowed_networks([])

    assert is_peer_allowed("203.0.113.9", networks)
    assert is_peer_allowed("", networks)


def test_ipv4_cidr_matches_members_only() -> None:
    networks = parse_allowed_networks(["10.0.0.0/8"])

    assert is_peer_allowed("10.1.2.3", networks)
    assert not is_peer_allowed("11.0.0.1", networks)


def test_single_host_entry_without_prefix_is_accepted() -> None:
    networks = parse_allowed_networks(["192.0.2.7"])

    assert is_peer_allowed("192.0.2.7", networks)
    assert not is_peer_allowed("192.0.2.8", networks)


def test_ipv6_network_is_supported() -> None:
    networks = parse_allowed_networks(["2001:db8::/32"])

    assert is_peer_allowed("2001:db8::5", networks)
    assert not is_peer_allowed("2001:db9::5", networks)


def test_ipv4_mapped_ipv6_peer_is_matched_against_ipv4_rules() -> None:
    # Dual-stack sockets report IPv4 clients as ::ffff:a.b.c.d.
    networks = parse_allowed_networks(["10.0.0.0/8"])

    assert is_peer_allowed("::ffff:10.0.0.5", networks)
    assert not is_peer_allowed("::ffff:172.16.0.5", networks)


def test_missing_peer_is_rejected_when_list_is_configured() -> None:
    networks = parse_allowed_networks(["10.0.0.0/8"])

    assert not is_peer_allowed("", networks)


def test_unparseable_peer_is_rejected_when_list_is_configured() -> None:
    networks = parse_allowed_networks(["10.0.0.0/8"])

    assert not is_peer_allowed("not-an-ip", networks)


@pytest.mark.parametrize("bad", ["10.0.0.0/33", "example.com", "10.0.0.256", "2001:db8::/129"])
def test_invalid_entries_are_rejected_at_parse_time(bad: str) -> None:
    with pytest.raises(ValueError, match="invalid receiver allowlist entry"):
        parse_allowed_networks([bad])


def test_entries_are_stripped_and_blank_entries_ignored() -> None:
    networks = parse_allowed_networks([" 10.0.0.0/8 ", "", "  "])

    assert len(networks) == 1
    assert is_peer_allowed("10.9.9.9", networks)
