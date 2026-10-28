"""The incident base model: stored fields, merge rules and report defaults.

One `Incident` subclass per type lives in
:mod:`opencanary_correlator.core.incident_model`; this module holds what they all
share, so the type registry is read without scrolling past the serialisation.
Persistence lives in :mod:`opencanary_correlator.core.incident`.
"""

from __future__ import annotations

import json
import logging
from typing import Any, ClassVar, Final

from pydantic import BaseModel, ConfigDict

from opencanary_correlator.constants import DEFAULT_LOGTYPE
from opencanary_correlator.core.incident_report import (
    render_report,
    render_report_short,
    render_title,
)
from opencanary_correlator.core.logdata import decode_logdata
from opencanary_correlator.enrichment.models import Enrichment
from opencanary_correlator.redaction import sanitize_text

logger = logging.getLogger("opencanary_correlator.core.incident")


#: A value echoed from a request can be arbitrarily long or contain newlines,
#: which would break the line layout of a plain-text report.
_MAX_REPORT_FIELD: Final[int] = 200


def _safe_field(value: Any) -> str:
    """Render one log value as a single clipped printable line."""
    return sanitize_text(value, limit=_MAX_REPORT_FIELD, collapse=True)


class Incident(BaseModel):
    """One correlated incident stored in Redis."""

    model_config = ConfigDict(extra="ignore")

    INCIDENT_NAME: ClassVar[str] = "incident"
    DESCRIPTION: ClassVar[str] = "Not available"
    # Whether every event appends exactly one entry to both `events_list` and
    # `logdata`, which is what makes a full timestamp list prove a full log list.
    # Port scans replace it with a deduplicated set that must stay exact.
    LOG_DATA_IS_APPEND_ONLY: ClassVar[bool] = True

    key: str
    node_id: str
    src_host: str = ""
    src_port: int = -1
    dst_host: str = ""
    dst_port: int = -1
    logtype: int = int(DEFAULT_LOGTYPE)
    created: int
    events_list: str = ""
    events_count: int = 1
    events_truncated: bool = False
    logdata: str | None = None
    acknowledged: bool = False
    notified: bool = False
    updated: bool = True
    description: str = ""
    #: Attacker-IP enrichment attached by the engine right before dispatch.
    #: Transient on purpose: `to_fields` builds its dict explicitly, so this
    #: never reaches Redis, and an incident rebuilt from a hash has it as None.
    enrichment: Enrichment | None = None

    # --- Formatting (ported string-for-string from the legacy code) ---------

    @property
    def display_description(self) -> str:
        """Human-facing incident name, falling back to the class constant.

        Incidents rebuilt from Redis may carry an empty `description` when the
        stored hash predates the field; alerts must still name the incident.
        """
        return self.description or self.DESCRIPTION

    def format_title(self) -> str:
        """One-line title used as an email/webhook subject."""
        return render_title(self.DESCRIPTION, self.src_host, self.node_id, self.dst_host)

    def format_report(self) -> str:
        """Full plain-text report."""
        return render_report(
            description=self.DESCRIPTION,
            created=self.created,
            src_host=self.src_host,
            dst_host=self.dst_host,
            node_id=self.node_id,
        )

    def format_report_short(self) -> str:
        """Compact report for size-limited channels."""
        return render_report_short(
            description=self.DESCRIPTION,
            src_host=self.src_host,
            node_id=self.node_id,
            dst_host=self.dst_host,
        )

    # --- Serialisation ------------------------------------------------------

    def to_fields(self) -> dict[str, str]:
        """Render the incident as Redis hash fields, legacy string shapes included."""
        fields = {
            "node_id": self.node_id,
            "src_host": self.src_host,
            "src_port": str(self.src_port),
            "dst_host": self.dst_host,
            "dst_port": str(self.dst_port),
            "logtype": str(self.logtype),
            "created": str(self.created),
            "events_list": self.events_list,
            "events_count": str(self.events_count),
            "acknowledged": str(self.acknowledged),
            "notified": str(self.notified),
            "updated": str(self.updated),
            "description": self.description or self.DESCRIPTION,
        }
        if self.logdata is not None:
            fields["logdata"] = self.logdata
        # Only written when they carry information, so small incidents keep the
        # exact legacy field set.
        if self.events_truncated:
            fields["events_truncated"] = "True"
        return fields

    @classmethod
    def from_fields(cls, key: str, fields: dict[str, str]) -> Incident:
        """Rebuild an incident from stored hash fields."""
        payload: dict[str, Any] = dict(fields)
        payload["key"] = key
        payload.setdefault("description", cls.DESCRIPTION)
        return cls.model_validate(payload)

    @classmethod
    def serialize_logdata(cls, value: Any) -> str:
        """Store new log data the way the legacy code did."""
        if isinstance(value, (list, tuple)):
            return json.dumps(list(value))
        return json.dumps([value])

    @staticmethod
    def append_timestamp(existing: str, now: int, *, limit: int) -> tuple[str, bool]:
        """Append one epoch to the legacy CSV, or keep it frozen at `limit`.

        Returns the stored CSV and whether it changed. Freezing (rather than
        trimming) keeps the cost of a merge constant once an incident is large,
        and leaves the first `limit` timestamps exactly as the console renders
        them.
        """
        entries = existing.split(",") if existing else []
        if len(entries) >= limit:
            return existing, False
        entries.append(str(now))
        return ",".join(entries), True

    @classmethod
    def trim_logdata(cls, value: str, *, limit: int) -> str:
        """Keep at most `limit` stored entries."""
        entries = decode_logdata(value)
        if len(entries) <= limit:
            return value
        return json.dumps(entries[:limit])

    @classmethod
    def merge_logdata(cls, existing: str | None, new: Any, *, limit: int) -> str:
        """Append one log entry, keeping at most `limit` stored entries.

        The stored list is frozen once the cap is reached, so a large incident
        stops rewriting (and replicating) its whole history on every event.
        """
        entries = decode_logdata(existing)
        if len(entries) < limit:
            entries.append(new)
            return json.dumps(entries)
        return existing or "[]"
