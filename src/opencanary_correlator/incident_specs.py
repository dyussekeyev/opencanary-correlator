"""The declarative table of incident types.

Everything that must agree about an incident type lives here once: the canonical
name used in alerts and `OCC_INCIDENT_HORIZONS`, the exported class name, the
legacy Redis key prefix and the human description. `core.incident_model` builds
its classes from this table and `constants.INCIDENT_KEY_PREFIX` is derived from
it, so a type cannot exist in one structure and be missing from another.

The module deliberately imports nothing from the package: it sits below both
`constants` and `core`, which is what lets them share it without a cycle.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True, slots=True)
class IncidentSpec:
    """One incident type, as stored and rendered."""

    #: Canonical name, e.g. `ftp.login_attempt`. Used in audit records, the
    #: `OCC_INCIDENT_HORIZONS` keys and `INCIDENT_TYPES`.
    name: str
    #: Name of the exported class, e.g. `IncidentFTPLogin`.
    class_name: str
    #: Legacy Redis key prefix, e.g. `incident:ftplogin:`.
    key_prefix: str
    #: Human description used in alert titles and reports.
    description: str


#: Every incident type, in the order the legacy console listed them.
INCIDENT_SPECS: Final[tuple[IncidentSpec, ...]] = (
    IncidentSpec(
        "ftp.login_attempt", "IncidentFTPLogin", "incident:ftplogin:", "FTP Login Attempt"
    ),
    IncidentSpec(
        "http.login_attempt", "IncidentHTTPLogin", "incident:httplogin:", "HTTP Login Attempt"
    ),
    IncidentSpec("http.request", "IncidentHTTPRequest", "incident:httprequest:", "HTTP Request"),
    IncidentSpec(
        "ssh.login_attempt", "IncidentSSHLogin", "incident:sshlogin:", "SSH Login Attempt"
    ),
    IncidentSpec(
        "telnet.login_attempt",
        "IncidentTelnetLogin",
        "incident:telnetlogin:",
        "Telnet Login Attempt",
    ),
    IncidentSpec(
        "httpproxy.login_attempt",
        "IncidentHTTPProxy",
        "incident:httpproxylogin:",
        "HTTP Proxy Login Attempt",
    ),
    IncidentSpec(
        "mysql.login_attempt", "IncidentMySQLLogin", "incident:mysqllogin:", "MySQL Login Attempt"
    ),
    IncidentSpec(
        "mssql.login_attempt", "IncidentMSSQLLogin", "incident:mssqllogin:", "MSSQL Login Attempt"
    ),
    IncidentSpec("tftp.action", "IncidentTFTP", "incident:tftp:", "tftp login Attempt"),
    IncidentSpec("ntp.monlist", "IncidentNTPMonList", "incident:ntpmonlist:", "NTP Login Attempt"),
    IncidentSpec(
        "vnc.login_attempt", "IncidentVNCLogin", "incident:vnclogin:", "VNC Login Attempt"
    ),
    IncidentSpec("snmp.cmd", "IncidentSNMP", "incident:snmplogin:", "SNMP Command Received"),
    IncidentSpec(
        "rdp.login_attempt", "IncidentRDPLogin", "incident:rdplogin:", "RDP Login Attempt"
    ),
    IncidentSpec(
        "sip.login_attempt", "IncidentSIPLogin", "incident:siplogin:", "SIP Login Attempt"
    ),
    IncidentSpec(
        "smb.file_open", "IncidentSMBFileOpen", "incident:smbfileopen:", "Shared File Opened"
    ),
    IncidentSpec(
        "scans.host_portscan", "IncidentHostPortScan", "incident:hostportscan:", "Host Port Scan"
    ),
    IncidentSpec(
        "scans.network_portscan",
        "IncidentNetworkPortScan",
        "incident:networkportscan:",
        "Network Port Scan",
    ),
)

#: Canonical incident name -> spec, for the class factory.
SPECS_BY_NAME: Final[dict[str, IncidentSpec]] = {spec.name: spec for spec in INCIDENT_SPECS}

#: Canonical incident name -> legacy Redis key prefix.
INCIDENT_KEY_PREFIX: Final[dict[str, str]] = {spec.name: spec.key_prefix for spec in INCIDENT_SPECS}


__all__ = ["INCIDENT_KEY_PREFIX", "INCIDENT_SPECS", "SPECS_BY_NAME", "IncidentSpec"]
