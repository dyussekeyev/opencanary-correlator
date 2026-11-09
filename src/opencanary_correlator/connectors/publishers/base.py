"""Contracts for publishers that send correlated incidents to external feeds."""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from typing import ClassVar

from opencanary_correlator.connectors.base import IncidentLike


class BasePublisher(ABC):
    """A feed that observes incidents independently of alert delivery.

    `observe` is called by the engine after the incident is stored and dispatch
    has settled. It must be cheap and must never raise into ingest: a publisher
    that is down cannot stop correlation or alerting. Durable fan-out happens
    inside the implementation, usually by writing a Redis queue.
    """

    name: ClassVar[str] = "publisher"

    @abstractmethod
    async def observe(self, incident: IncidentLike) -> None:
        """Record one incident for later publication."""

    @property
    def critical_tasks(self) -> tuple[asyncio.Task[None], ...]:
        """Long-lived background flushers supervised by the runtime."""
        return ()

    async def start(self) -> None:  # noqa: B027 - optional hook
        """Start background work, if any."""

    async def stop(self) -> None:  # noqa: B027 - optional hook
        """Stop background work without discarding durable queue state."""

    async def aclose(self) -> None:  # noqa: B027 - optional hook
        """Release network resources."""


__all__ = ["BasePublisher"]
