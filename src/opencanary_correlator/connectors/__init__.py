"""Input receivers and output dispatchers, unified by the contracts in `base`."""

from __future__ import annotations

from opencanary_correlator.connectors.base import (
    AllowAllRateLimiter,
    BaseDispatcher,
    BaseReceiver,
    ConnectorRegistry,
    DispatchResult,
    EventSink,
    IncidentLike,
    RateLimiter,
)

__all__ = [
    "AllowAllRateLimiter",
    "BaseDispatcher",
    "BaseReceiver",
    "ConnectorRegistry",
    "DispatchResult",
    "EventSink",
    "IncidentLike",
    "RateLimiter",
]
