"""Incident types: the custom subclasses and the registry that binds them.

`Incident` itself, its stored fields and its merge rules live in
:mod:`opencanary_correlator.core.incident_base`. This module keeps the four types
whose rendering or merging is specific, the generated classes for the types that
`incident_specs` describes, and the registry both are built into.
"""

from __future__ import annotations

import json
from typing import Any, Final

from opencanary_correlator.constants import LogType
from opencanary_correlator.core.incident_base import Incident, _safe_field, logger
from opencanary_correlator.core.incident_report import (
    render_report,
    render_report_short,
    render_scan_report,
)
from opencanary_correlator.core.logdata import decode_logdata
from opencanary_correlator.incident_specs import INCIDENT_SPECS, IncidentSpec


class IncidentHTTPRequest(Incident):
    """A request that reached the canary HTTP service (log types 3000/3002/3003)."""

    INCIDENT_NAME = "http.request"
    DESCRIPTION = "HTTP Request"

    def _http_details(self) -> tuple[str, str, str, str] | None:
        """Return `(method, path, host, user agent)` from the first log entry."""
        try:
            entry = decode_logdata(self.logdata)[0]
        except (IndexError, TypeError):
            logger.error("Could not extract HTTP request details from incident %s", self.key)
            return None
        if not isinstance(entry, dict):
            logger.error("Could not extract HTTP request details from incident %s", self.key)
            return None
        method = entry.get("METHOD")
        if not method and int(self.logtype) == int(LogType.LOG_HTTP_GET):
            # A 3000 event is a GET by definition; older canaries omit the field.
            method = "GET"
        return (
            _safe_field(method or ""),
            _safe_field(entry.get("PATH", "")),
            _safe_field(entry.get("HOST", "")),
            _safe_field(entry.get("USERAGENT", "")),
        )

    def format_report(self) -> str:
        details = self._http_details()
        if details is None:
            return super().format_report()
        method, path, host, agent = details
        extra = (
            "".join(
                f"  {label:<8}: {value}\n"
                for label, value in (
                    ("Method", method),
                    ("Path", path),
                    ("Host", host),
                    ("Agent", agent),
                )
                if value
            )
            + "\n"
        )
        return render_report(
            description=self.DESCRIPTION,
            created=self.created,
            src_host=self.src_host,
            dst_host=self.dst_host,
            node_id=self.node_id,
            extra=extra,
        )

    def format_report_short(self) -> str:
        details = self._http_details()
        if details is None:
            return super().format_report_short()
        method, path, host, _agent = details
        request = f'{method} "{path}"'.strip() if method else f'"{path}"'
        suffix = f" on {host}" if host else ""
        return super().format_report_short().rstrip(".") + f". Request {request}{suffix}."


class IncidentSMBFileOpen(Incident):
    INCIDENT_NAME = "smb.file_open"
    DESCRIPTION = "Shared File Opened"

    def _smb_details(self) -> tuple[str, str] | None:
        try:
            entry = decode_logdata(self.logdata)[0]
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
        values = {int(value) for value in decode_logdata(existing)}
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
        values = {str(value) for value in decode_logdata(existing)}
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
            targets = ", ".join(str(host) for host in decode_logdata(self.logdata))
        except TypeError:
            targets = "Target data absent"
        return render_scan_report(
            description=self.DESCRIPTION,
            created=self.created,
            src_host=self.src_host,
            dst_port=self.dst_port,
            targets=targets,
        )


#: Types whose behaviour is more than the base report and are declared above.
_CUSTOM_INCIDENTS: Final[tuple[type[Incident], ...]] = (
    IncidentHTTPRequest,
    IncidentSMBFileOpen,
    IncidentHostPortScan,
    IncidentNetworkPortScan,
)


def _simple_incident(spec: IncidentSpec) -> type[Incident]:
    """Build the class for an incident type that needs no custom behaviour.

    The name, description and key prefix live in `incident_specs`, so a type that
    is listed there cannot be missing from the registry or from the prefix map.
    """
    return type(
        spec.class_name,
        (Incident,),
        {
            "__module__": __name__,
            "__doc__": f"Incident for `{spec.name}`.",
            "INCIDENT_NAME": spec.name,
            "DESCRIPTION": spec.description,
        },
    )


_CUSTOM_NAMES: Final[frozenset[str]] = frozenset(
    incident_cls.INCIDENT_NAME for incident_cls in _CUSTOM_INCIDENTS
)

INCIDENT_TYPES: Final[dict[str, type[Incident]]] = {
    **{
        spec.name: _simple_incident(spec)
        for spec in INCIDENT_SPECS
        if spec.name not in _CUSTOM_NAMES
    },
    **{incident_cls.INCIDENT_NAME: incident_cls for incident_cls in _CUSTOM_INCIDENTS},
}

# The exported names stay real module attributes: imports, `isinstance` checks and
# tracebacks keep working, while the metadata has a single owner.
IncidentFTPLogin: Final[type[Incident]] = INCIDENT_TYPES["ftp.login_attempt"]
IncidentHTTPLogin: Final[type[Incident]] = INCIDENT_TYPES["http.login_attempt"]
IncidentSSHLogin: Final[type[Incident]] = INCIDENT_TYPES["ssh.login_attempt"]
IncidentTelnetLogin: Final[type[Incident]] = INCIDENT_TYPES["telnet.login_attempt"]
IncidentHTTPProxy: Final[type[Incident]] = INCIDENT_TYPES["httpproxy.login_attempt"]
IncidentMySQLLogin: Final[type[Incident]] = INCIDENT_TYPES["mysql.login_attempt"]
IncidentMSSQLLogin: Final[type[Incident]] = INCIDENT_TYPES["mssql.login_attempt"]
IncidentTFTP: Final[type[Incident]] = INCIDENT_TYPES["tftp.action"]
IncidentNTPMonList: Final[type[Incident]] = INCIDENT_TYPES["ntp.monlist"]
IncidentVNCLogin: Final[type[Incident]] = INCIDENT_TYPES["vnc.login_attempt"]
IncidentSNMP: Final[type[Incident]] = INCIDENT_TYPES["snmp.cmd"]
IncidentRDPLogin: Final[type[Incident]] = INCIDENT_TYPES["rdp.login_attempt"]
IncidentSIPLogin: Final[type[Incident]] = INCIDENT_TYPES["sip.login_attempt"]

__all__ = [
    "INCIDENT_TYPES",
    "Incident",
    "IncidentFTPLogin",
    "IncidentHTTPLogin",
    "IncidentHTTPProxy",
    "IncidentHTTPRequest",
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
