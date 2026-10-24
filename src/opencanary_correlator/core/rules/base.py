"""Rule contract shared by every correlation rule."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from opencanary_correlator.core.incident import Incident
from opencanary_correlator.schemas import CanaryEvent


class Rule(ABC):
    """A correlation rule.

    Rules own no state: matching happens against a validated event and every
    window lives in Redis.
    """

    name: ClassVar[str] = "rule"

    @abstractmethod
    def matches(self, event: CanaryEvent) -> bool:
        """Return True when this rule handles the event."""

    @abstractmethod
    async def apply(self, event: CanaryEvent, *, now: float) -> list[Incident]:
        """Apply the rule, returning incidents that need a notification."""


__all__ = ["Rule"]
