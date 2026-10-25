"""Incident models, legacy report formatting and atomic persistence.

Incident hashes keep the exact field names and value shapes the legacy console
reads (`events_list` as a CSV of epochs, `logdata` as a JSON string, booleans
stored as ``"True"``/``"False"``). Creation and merging are serialised through
a Redis lock so two replicas can never both notify about the same incident.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, ClassVar, Final

from pydantic import BaseModel, ConfigDict

from opencanary_correlator.audit import AuditLogger
from opencanary_correlator.config import Settings
from opencanary_correlator.constants import DEFAULT_LOGTYPE
from opencanary_correlator.schemas import CanaryEvent
from opencanary_correlator.storage import keys
from opencanary_correlator.storage.redis_store import RedisStore

logger = logging.getLogger(__name__)

_UNSET: Final[object] = object()


def _entries(existing: str | None) -> list[Any]:
    """Decode the stored `logdata` list, tolerating legacy shapes."""
    if not existing:
        return []
    try:
        parsed = json.loads(existing)
    except json.JSONDecodeError:
        return []
    if isinstance(parsed, list):
        return parsed
    return [parsed]


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

    # --- Formatting (ported string-for-string from the legacy code) ---------

    def format_title(self) -> str:
        """One-line title used as an email/webhook subject."""
        return f"{self.DESCRIPTION} by {self.src_host} on {self.node_id} ({self.dst_host})"

    def _format_report(self) -> str:
        created = datetime.fromtimestamp(self.created, tz=UTC).strftime("%Y-%m-%d %H:%M:%S (UTC)")
        return f"""
======================================================================
                                ALERT
======================================================================

  Incident: {self.DESCRIPTION}
  Time    : {created}
  Source  : {self.src_host}
  Target  : {self.dst_host} (id {self.node_id})
  EXTRA
======================================================================
"""

    def format_report(self) -> str:
        """Full plain-text report."""
        return self._format_report().replace("  EXTRA", "")

    def _format_report_short(self) -> str:
        return (
            f"Canary Incident: {self.DESCRIPTION}. Source {self.src_host}. "
            f"Target {self.node_id} ({self.dst_host}).EXTRA"
        )

    def format_report_short(self) -> str:
        """Compact report for size-limited channels."""
        return self._format_report_short().replace("EXTRA", "")

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
        entries = _entries(value)
        if len(entries) <= limit:
            return value
        return json.dumps(entries[:limit])

    @classmethod
    def merge_logdata(cls, existing: str | None, new: Any, *, limit: int) -> str:
        """Append one log entry, keeping at most `limit` stored entries.

        The stored list is frozen once the cap is reached, so a large incident
        stops rewriting (and replicating) its whole history on every event.
        """
        entries = _entries(existing)
        if len(entries) < limit:
            entries.append(new)
            return json.dumps(entries)
        return existing or "[]"


class IncidentFTPLogin(Incident):
    INCIDENT_NAME = "ftp.login_attempt"
    DESCRIPTION = "FTP Login Attempt"


class IncidentHTTPLogin(Incident):
    INCIDENT_NAME = "http.login_attempt"
    DESCRIPTION = "HTTP Login Attempt"


class IncidentSSHLogin(Incident):
    INCIDENT_NAME = "ssh.login_attempt"
    DESCRIPTION = "SSH Login Attempt"


class IncidentTelnetLogin(Incident):
    INCIDENT_NAME = "telnet.login_attempt"
    DESCRIPTION = "Telnet Login Attempt"


class IncidentHTTPProxy(Incident):
    INCIDENT_NAME = "httpproxy.login_attempt"
    DESCRIPTION = "HTTP Proxy Login Attempt"


class IncidentMySQLLogin(Incident):
    INCIDENT_NAME = "mysql.login_attempt"
    DESCRIPTION = "MySQL Login Attempt"


class IncidentMSSQLLogin(Incident):
    INCIDENT_NAME = "mssql.login_attempt"
    DESCRIPTION = "MSSQL Login Attempt"


class IncidentTFTP(Incident):
    INCIDENT_NAME = "tftp.action"
    DESCRIPTION = "tftp login Attempt"


class IncidentNTPMonList(Incident):
    INCIDENT_NAME = "ntp.monlist"
    DESCRIPTION = "NTP Login Attempt"


class IncidentVNCLogin(Incident):
    INCIDENT_NAME = "vnc.login_attempt"
    DESCRIPTION = "VNC Login Attempt"


class IncidentSNMP(Incident):
    INCIDENT_NAME = "snmp.cmd"
    DESCRIPTION = "SNMP Command Received"


class IncidentRDPLogin(Incident):
    INCIDENT_NAME = "rdp.login_attempt"
    DESCRIPTION = "RDP Login Attempt"


class IncidentSIPLogin(Incident):
    INCIDENT_NAME = "sip.login_attempt"
    DESCRIPTION = "SIP Login Attempt"


class IncidentSMBFileOpen(Incident):
    INCIDENT_NAME = "smb.file_open"
    DESCRIPTION = "Shared File Opened"

    def _smb_details(self) -> tuple[str, str] | None:
        try:
            entry = _entries(self.logdata)[0]
            if not isinstance(entry, dict):
                return None
            return str(entry.get("FILENAME", "")), str(entry.get("USER", ""))
        except (IndexError, TypeError):
            logger.error("Could not extract SMB filename from log data: %r", self.logdata)
            return None

    def format_report(self) -> str:
        details = self._smb_details()
        if details is None:
            return super().format_report()
        filename, user = details
        return self._format_report().replace(
            "  EXTRA", f"  File    : {filename}\n  User    : {user}\n"
        )

    def format_report_short(self) -> str:
        details = self._smb_details()
        if details is None:
            return super().format_report_short()
        filename, user = details
        return self._format_report_short().replace("EXTRA", f' File "{filename}", user "{user}".')


class IncidentHostPortScan(Incident):
    INCIDENT_NAME = "scans.host_portscan"
    DESCRIPTION = "Host Port Scan"
    LOG_DATA_IS_APPEND_ONLY = False

    @classmethod
    def merge_logdata(cls, existing: str | None, new: Any, *, limit: int) -> str:
        """Merge distinct ports, keeping every member.

        A scan logs one entry per distinct port, not per event, so this list is
        bounded by the port universe rather than by event volume; dropping
        members would destroy the evidence the incident exists to record.
        """
        values = {int(value) for value in _entries(existing)}
        incoming = new if isinstance(new, (list, tuple)) else [new]
        values.update(int(value) for value in incoming)
        return json.dumps(sorted(values))

    @classmethod
    def trim_logdata(cls, value: str, *, limit: int) -> str:
        """Scan evidence is never truncated."""
        return value


class IncidentNetworkPortScan(Incident):
    INCIDENT_NAME = "scans.network_portscan"
    DESCRIPTION = "Network Port Scan"
    LOG_DATA_IS_APPEND_ONLY = False

    @classmethod
    def merge_logdata(cls, existing: str | None, new: Any, *, limit: int) -> str:
        """Merge distinct targets; like the host scan this list stays exact."""
        values = {str(value) for value in _entries(existing)}
        incoming = new if isinstance(new, (list, tuple)) else [new]
        values.update(str(value) for value in incoming)
        return json.dumps(sorted(values))

    @classmethod
    def trim_logdata(cls, value: str, *, limit: int) -> str:
        """Scan evidence is never truncated."""
        return value

    def format_report(self) -> str:
        """Formatting used by the legacy alert for distributed scans."""
        try:
            targets = ", ".join(str(host) for host in _entries(self.logdata))
        except TypeError:
            targets = "Target data absent"
        return f"""
======================================================================
                                ALERT
======================================================================

  Incident: {self.DESCRIPTION}
  Time    : {self.created}
  Source  : {self.src_host}
  Port    : {self.dst_port}
  Targets : {targets}

======================================================================
"""


INCIDENT_TYPES: Final[dict[str, type[Incident]]] = {
    incident_cls.INCIDENT_NAME: incident_cls
    for incident_cls in (
        IncidentFTPLogin,
        IncidentHTTPLogin,
        IncidentSSHLogin,
        IncidentTelnetLogin,
        IncidentHTTPProxy,
        IncidentMySQLLogin,
        IncidentMSSQLLogin,
        IncidentTFTP,
        IncidentNTPMonList,
        IncidentVNCLogin,
        IncidentSNMP,
        IncidentRDPLogin,
        IncidentSIPLogin,
        IncidentSMBFileOpen,
        IncidentHostPortScan,
        IncidentNetworkPortScan,
    )
}

__all__ = [
    "INCIDENT_TYPES",
    "Incident",
    "IncidentFTPLogin",
    "IncidentHTTPLogin",
    "IncidentHTTPProxy",
    "IncidentHostPortScan",
    "IncidentMSSQLLogin",
    "IncidentMySQLLogin",
    "IncidentNTPMonList",
    "IncidentNetworkPortScan",
    "IncidentRDPLogin",
    "IncidentRepository",
    "IncidentSIPLogin",
    "IncidentSMBFileOpen",
    "IncidentSNMP",
    "IncidentSSHLogin",
    "IncidentTFTP",
    "IncidentTelnetLogin",
    "IncidentVNCLogin",
]


class IncidentRepository:
    """Create or merge incidents in Redis, exactly once per source host."""

    def __init__(
        self,
        store: RedisStore,
        settings: Settings,
        audit: AuditLogger,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._store = store
        self._settings = settings
        self._audit = audit
        self._clock = clock

    async def record(
        self,
        incident_name: str,
        event: CanaryEvent,
        *,
        logdata: Any = _UNSET,
        logtype: int | None = None,
    ) -> Incident | None:
        """Persist a new incident, or merge into the live one.

        Returns the incident only when it was created: merged events must not
        trigger another notification.
        """
        incident_cls = INCIDENT_TYPES[incident_name]
        now = int(self._clock())
        horizon = self._settings.horizon_for(incident_name)
        # The trailing colon is part of the key grammar: matching only the host
        # prefix would also match hosts that merely start with it (10.0.0.5
        # would merge into an incident for 10.0.0.55).
        prefix = f"{keys.incident_prefix(incident_name, event.src_host)}:"
        pointer_key = keys.incident_latest_key(incident_name, event.src_host)
        new_logdata = event.logdata if logdata is _UNSET else logdata
        resolved_logtype = logtype if logtype is not None else int(event.logtype)

        async with self._store.lock(
            keys.incident_lock_key(incident_name, event.src_host)
        ) as acquired:
            if not acquired:
                self._audit.emit(
                    "incident_lock_timeout",
                    "error",
                    {"incident": incident_name, "src_host": event.src_host},
                )
                return None

            scan_limit = self._settings.incident_lookup_scan_limit
            lookup = await self._store.find_recent_incident(
                prefix,
                min_score=now - horizon,
                pointer_key=pointer_key,
                scan_limit=scan_limit,
            )
            if lookup.key is None and lookup.truncated:
                # The capped scan missed, but a live incident for this host can
                # sit behind the cap (a pointerless incident from an older build).
                # Creating a second one would duplicate the alert and the
                # notification, so read the whole horizon window before deciding.
                lookup = await self._store.find_recent_incident(
                    prefix,
                    min_score=now - horizon,
                    pointer_key=None,
                    scan_limit=None,
                )
            existing_key = lookup.key
            if existing_key is not None:
                fields = await self._store.hgetall(existing_key)
                if fields:
                    cap = self._settings.max_stored_events
                    merged = incident_cls.from_fields(existing_key, fields)
                    # A stored incident is frozen once its timestamp list is full.
                    # The flag plus a count already at the cap answer that without
                    # splitting the CSV, and when the cap was raised in the
                    # meantime the count is below it, so recording resumes.
                    frozen = merged.events_truncated and merged.events_count >= cap
                    if not frozen:
                        merged.events_list, appended = incident_cls.append_timestamp(
                            merged.events_list, now, limit=cap
                        )
                        frozen = not appended
                    merged.events_count += 1
                    merged.updated = True
                    merged.events_truncated = merged.events_truncated or frozen
                    if frozen and incident_cls.LOG_DATA_IS_APPEND_ONLY:
                        # One event adds one timestamp and one log entry, capped at
                        # the same limit, so a full timestamp list means
                        # `merge_logdata` would decode the whole stored list (44-46
                        # us of a ~51 us merge) only to return it unchanged. For a
                        # frozen history the decode is discarded, so it is skipped.
                        logdata_changed = False
                    else:
                        stored_logdata = incident_cls.merge_logdata(
                            merged.logdata, new_logdata, limit=cap
                        )
                        logdata_changed = stored_logdata != (merged.logdata or "")
                        merged.logdata = stored_logdata
                    if merged.events_truncated:
                        # The stored history is full: send the counters only, so a
                        # 10k-event incident stops costing a full-field rewrite
                        # (and a full-field replication) on every event.
                        updates: dict[str, str] = {
                            "events_count": str(merged.events_count),
                            "events_truncated": "True",
                            "updated": "True",
                        }
                        if not frozen:
                            updates["events_list"] = merged.events_list
                        if logdata_changed:
                            updates["logdata"] = merged.logdata or "[]"
                    else:
                        updates = merged.to_fields()
                    await self._store.save_incident(
                        existing_key,
                        updates,
                        score=now,
                        pointer_key=pointer_key,
                    )
                    self._audit.emit(
                        "incident_updated",
                        "info",
                        {
                            "incident": incident_name,
                            "key": existing_key,
                            "events_count": merged.events_count,
                            "events_truncated": merged.events_truncated,
                        },
                    )
                    return None

            key = keys.incident_key(incident_name, event.src_host, now)
            cap = self._settings.max_stored_events
            initial_logdata = incident_cls.trim_logdata(
                incident_cls.serialize_logdata(new_logdata), limit=cap
            )
            incident = incident_cls(
                key=key,
                node_id=event.node_id,
                src_host=event.src_host,
                src_port=event.src_port,
                dst_host=event.dst_host,
                dst_port=event.dst_port,
                logtype=resolved_logtype,
                created=now,
                events_list=str(now),
                events_count=1,
                logdata=initial_logdata,
                description=incident_cls.DESCRIPTION,
            )
            await self._store.save_incident(
                key, incident.to_fields(), score=now, pointer_key=pointer_key
            )
            self._audit.emit(
                "incident_created",
                "info",
                {
                    "incident": incident_name,
                    "key": key,
                    "node_id": event.node_id,
                    "src_host": event.src_host,
                },
            )
            return incident
