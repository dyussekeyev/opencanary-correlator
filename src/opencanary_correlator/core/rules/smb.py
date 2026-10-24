"""Rule for SMB shared-file access."""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from opencanary_correlator.constants import LogType
from opencanary_correlator.core.incident import Incident, IncidentRepository
from opencanary_correlator.core.rules.base import Rule
from opencanary_correlator.schemas import CanaryEvent


@dataclass(frozen=True, slots=True)
class SmbFileOpenRule(Rule):
    """Create (or merge) a `smb.file_open` incident."""

    repository: IncidentRepository

    name: ClassVar[str] = "smb_file_open"

    def matches(self, event: CanaryEvent) -> bool:
        """True for `LOG_SMB_FILE_OPEN` events."""
        return int(event.logtype) == int(LogType.LOG_SMB_FILE_OPEN)

    async def apply(self, event: CanaryEvent, *, now: float) -> list[Incident]:
        """Record the event, notifying only for a new incident."""
        incident = await self.repository.record("smb.file_open", event)
        return [incident] if incident is not None else []


__all__ = ["SmbFileOpenRule"]
