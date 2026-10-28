"""Incident domain model: one class per incident type and its type registry.

Each `Incident` subclass knows how to merge its own `logdata`, how to render
its legacy report and which Redis hash fields it owns. Persistence lives in
`opencanary_correlator.core.incident`.
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
    render_scan_report,
    render_title,
)

logger = logging.getLogger("opencanary_correlator.core.incident")


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
            # Never log `logdata` itself: for an SMB incident it can hold a
            # captured password, and this message goes to stderr and the log file.
            logger.error("Could not extract the SMB file name from incident %s", self.key)
            return None

    def format_report(self) -> str:
        details = self._smb_details()
        if details is None:
            return super().format_report()
        filename, user = details
        return render_report(
            description=self.DESCRIPTION,
            created=self.created,
            src_host=self.src_host,
            dst_host=self.dst_host,
            node_id=self.node_id,
            extra=f"  File    : {filename}\n  User    : {user}\n",
        )

    def format_report_short(self) -> str:
        details = self._smb_details()
        if details is None:
            return super().format_report_short()
        filename, user = details
        return render_report_short(
            description=self.DESCRIPTION,
            src_host=self.src_host,
            node_id=self.node_id,
            dst_host=self.dst_host,
            extra=f' File "{filename}", user "{user}".',
        )


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
        return render_scan_report(
            description=self.DESCRIPTION,
            created=self.created,
            src_host=self.src_host,
            dst_port=self.dst_port,
            targets=targets,
        )


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
    "IncidentSIPLogin",
    "IncidentSMBFileOpen",
    "IncidentSNMP",
    "IncidentSSHLogin",
    "IncidentTFTP",
    "IncidentTelnetLogin",
    "IncidentVNCLogin",
]
