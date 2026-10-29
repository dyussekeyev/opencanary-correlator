"""Rule for SMB shared-file access."""

from __future__ import annotations

from collections.abc import Collection
from dataclasses import dataclass
from typing import ClassVar

from opencanary_correlator import metrics
from opencanary_correlator.audit import AuditLogger
from opencanary_correlator.constants import LogType
from opencanary_correlator.core.incident import Incident, IncidentRepository
from opencanary_correlator.core.rules.base import Rule
from opencanary_correlator.schemas import CanaryEvent, SmbFileOpenData


@dataclass(frozen=True, slots=True)
class SmbFileOpenRule(Rule):
    """Create (or merge) a `smb.file_open` incident.

    Samba's audit log records a row per filesystem operation, so one share
    browsed by one client produces `connect`, `flistxattr` and `openat` rows
    before anything is actually opened. `ignored_actions` lets an operator drop
    the rows that carry no signal (empty by default: an upgrade never changes
    which events are correlated). A dropped event is counted and audited with
    `reason=smb_action`, so a suppression never looks like a lost event.
    """

    repository: IncidentRepository
    ignored_actions: frozenset[str] = frozenset()
    audit: AuditLogger | None = None

    name: ClassVar[str] = "smb_file_open"

    def matches(self, event: CanaryEvent) -> bool:
        """True for `LOG_SMB_FILE_OPEN` events."""
        return int(event.logtype) == int(LogType.LOG_SMB_FILE_OPEN)

    async def apply(self, event: CanaryEvent, *, now: float) -> list[Incident]:
        """Record the event, notifying only for a new incident."""
        action = self._action(event)
        if action and action in self.ignored_actions:
            metrics.EVENTS_IGNORED.labels(reason="smb_action").inc()
            if self.audit is not None:
                self.audit.emit(
                    "event_ignored",
                    "info",
                    {
                        "reason": "smb_action",
                        "action": action,
                        "node_id": event.node_id,
                        "src_host": event.src_host,
                    },
                )
            return []
        incident = await self.repository.record("smb.file_open", event)
        return [incident] if incident is not None else []

    @staticmethod
    def _action(event: CanaryEvent) -> str:
        """Return the audit action of the event, lower-cased, or an empty string."""
        try:
            data = SmbFileOpenData.from_logdata(event.logdata)
        except ValueError:
            # A shape the typed view refuses (a nested object where a string is
            # expected) must not fail the rule: correlate it as before.
            return ""
        return data.AUDITACTION.strip().lower()


def build_smb_rule(
    repository: IncidentRepository,
    ignored_actions: Collection[str] = (),
    audit: AuditLogger | None = None,
) -> SmbFileOpenRule:
    """Build the SMB rule with a normalised ignore set."""
    return SmbFileOpenRule(
        repository=repository,
        ignored_actions=frozenset(action.lower() for action in ignored_actions if action),
        audit=audit,
    )


__all__ = ["SmbFileOpenRule", "build_smb_rule"]
