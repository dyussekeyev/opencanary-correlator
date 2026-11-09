"""Outbound threat-intelligence publishers.

A publisher is deliberately separate from an alert dispatcher: it has its own
durable queue, its own retry and publication policy, and it is never gated by
the notification budget. The first implementation publishes honeypot
observations to MISP; the package keeps the contract small so another feed can
be added without touching the correlation engine.
"""

from opencanary_correlator.connectors.publishers.base import BasePublisher
from opencanary_correlator.connectors.publishers.misp import (
    MispClientError,
    MispExistingAttribute,
    MispObservation,
    MispPublisher,
    MispPublisherError,
)

__all__ = [
    "BasePublisher",
    "MispClientError",
    "MispExistingAttribute",
    "MispObservation",
    "MispPublisher",
    "MispPublisherError",
]
