"""Rules for single-event incidents (login attempts and similar)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Final

from opencanary_correlator.constants import LogType
from opencanary_correlator.core.incident import Incident, IncidentRepository
from opencanary_correlator.core.rules.base import Rule
from opencanary_correlator.schemas import CanaryEvent

#: Log type -> incident name, mirroring the legacy `logmap`.
LOGIN_INCIDENTS: Final[dict[int, str]] = {
    int(LogType.LOG_FTP_LOGIN_ATTEMPT): "ftp.login_attempt",
    int(LogType.LOG_HTTP_POST_LOGIN_ATTEMPT): "http.login_attempt",
    int(LogType.LOG_SSH_LOGIN_ATTEMPT): "ssh.login_attempt",
    int(LogType.LOG_TELNET_LOGIN_ATTEMPT): "telnet.login_attempt",
    int(LogType.LOG_HTTPPROXY_LOGIN_ATTEMPT): "httpproxy.login_attempt",
    int(LogType.LOG_MYSQL_LOGIN_ATTEMPT): "mysql.login_attempt",
    int(LogType.LOG_MSSQL_LOGIN_SQLAUTH): "mssql.login_attempt",
    int(LogType.LOG_MSSQL_LOGIN_WINAUTH): "mssql.login_attempt",
    int(LogType.LOG_TFTP): "tftp.action",
    int(LogType.LOG_NTP_MONLIST): "ntp.monlist",
    int(LogType.LOG_VNC): "vnc.login_attempt",
    int(LogType.LOG_SNMP_CMD): "snmp.cmd",
    int(LogType.LOG_RDP): "rdp.login_attempt",
    int(LogType.LOG_SIP_REQUEST): "sip.login_attempt",
}


@dataclass(frozen=True, slots=True)
class LoginRule(Rule):
    """Create (or merge) an incident for one log type."""

    incident_name: str
    logtype: int
    repository: IncidentRepository

    name: ClassVar[str] = "login"

    def matches(self, event: CanaryEvent) -> bool:
        """True when the event log type is the one handled by this rule."""
        return int(event.logtype) == self.logtype

    async def apply(self, event: CanaryEvent, *, now: float) -> list[Incident]:
        """Record the event, notifying only when a new incident is created."""
        incident = await self.repository.record(self.incident_name, event)
        return [incident] if incident is not None else []


def build_login_rules(repository: IncidentRepository) -> list[LoginRule]:
    """Build one rule per known login-style log type."""
    return [
        LoginRule(incident_name=incident_name, logtype=logtype, repository=repository)
        for logtype, incident_name in LOGIN_INCIDENTS.items()
    ]


__all__ = ["LOGIN_INCIDENTS", "LoginRule", "build_login_rules"]
