"""Source-address allowlist shared by the network receivers.

An empty allowlist accepts every peer, which keeps the default behaviour
unchanged. Once any network is configured, a peer is accepted only when its
address falls inside one of them; a missing or unparseable peer address is
rejected in that case.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from typing import TypeAlias

IPNetwork: TypeAlias = ipaddress.IPv4Network | ipaddress.IPv6Network
AllowedNetworks: TypeAlias = tuple[IPNetwork, ...]

PEER_NOT_ALLOWED = "peer_not_allowed"


def parse_allowed_networks(entries: Iterable[str]) -> AllowedNetworks:
    """Parse CIDR or bare-address entries, raising ValueError on any invalid one."""
    networks: list[IPNetwork] = []
    for raw in entries:
        entry = raw.strip()
        if not entry:
            continue
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError as exc:
            raise ValueError(f"invalid receiver allowlist entry: {entry!r}") from exc
    return tuple(networks)


def is_peer_allowed(peer_ip: str, networks: AllowedNetworks) -> bool:
    """Return True when `peer_ip` may be accepted under `networks`."""
    if not networks:
        return True
    try:
        address = ipaddress.ip_address(peer_ip)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        # Dual-stack sockets report IPv4 clients as ::ffff:a.b.c.d.
        address = address.ipv4_mapped
    return any(address in network for network in networks)


__all__ = [
    "PEER_NOT_ALLOWED",
    "AllowedNetworks",
    "IPNetwork",
    "is_peer_allowed",
    "parse_allowed_networks",
]
