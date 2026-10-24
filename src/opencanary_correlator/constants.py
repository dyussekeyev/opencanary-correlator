"""Log type registry and legacy-compatible constants.

The numeric values are part of the OpenCanary wire format: a canary node sends
`logtype` as a plain integer, so these numbers must never be renumbered. Values
0-15001 come from the original correlator; the remaining ones mirror
`opencanary/logger.py` in the upstream project.
"""

from __future__ import annotations

from enum import IntEnum
from typing import Any, Final


class LogType(IntEnum):
    """Known OpenCanary log types.

    Unknown integers are still accepted by :class:`opencanary_correlator.schemas.CanaryEvent`;
    this enum only names the ones the correlator knows how to route.
    """

    LOG_INVALID = 0

    LOG_BASE_BOOT = 1000
    LOG_BASE_MSG = 1001
    LOG_BASE_DEBUG = 1002
    LOG_BASE_ERROR = 1003
    LOG_BASE_PING = 1004
    LOG_BASE_CONFIG_SAVE = 1005
    LOG_BASE_EXAMPLE = 1006

    LOG_FTP_LOGIN_ATTEMPT = 2000
    LOG_FTP_AUTH_ATTEMPT_INITIATED = 2001

    LOG_HTTP_GET = 3000
    LOG_HTTP_POST_LOGIN_ATTEMPT = 3001
    LOG_HTTP_UNIMPLEMENTED_METHOD = 3002
    LOG_HTTP_REDIRECT = 3003

    LOG_SSH_NEW_CONNECTION = 4000
    LOG_SSH_REMOTE_VERSION_SENT = 4001
    LOG_SSH_LOGIN_ATTEMPT = 4002

    LOG_SMB_FILE_OPEN = 5000
    LOG_PORT_SYN = 5001
    LOG_PORT_NMAPOS = 5002
    LOG_PORT_NMAPNULL = 5003
    LOG_PORT_NMAPXMAS = 5004
    LOG_PORT_NMAPFIN = 5005

    LOG_TELNET_LOGIN_ATTEMPT = 6001
    LOG_TELNET_CONNECTION_MADE = 6002

    LOG_HTTPPROXY_LOGIN_ATTEMPT = 7001

    LOG_MYSQL_LOGIN_ATTEMPT = 8001

    LOG_MSSQL_LOGIN_SQLAUTH = 9001
    LOG_MSSQL_LOGIN_WINAUTH = 9002
    LOG_MYSQL_CONNECTION_MADE = 9003

    LOG_TFTP = 10001
    LOG_NTP_MONLIST = 11001
    LOG_VNC = 12001
    LOG_SNMP_CMD = 13001
    LOG_RDP = 14001
    LOG_SIP_REQUEST = 15001
    LOG_GIT_CLONE_REQUEST = 16001
    LOG_REDIS_COMMAND = 17001

    LOG_TCP_BANNER_CONNECTION_MADE = 18001
    LOG_TCP_BANNER_KEEP_ALIVE_CONNECTION_MADE = 18002
    LOG_TCP_BANNER_KEEP_ALIVE_SECRET_RECEIVED = 18003
    LOG_TCP_BANNER_KEEP_ALIVE_DATA_RECEIVED = 18004
    LOG_TCP_BANNER_DATA_RECEIVED = 18005

    LOG_LLMNR_QUERY_RESPONSE = 19001
    LOG_MONGODB_LOGIN_ATTEMPT = 20001

    LOG_USER_0 = 99000
    LOG_USER_1 = 99001
    LOG_USER_2 = 99002
    LOG_USER_3 = 99003
    LOG_USER_4 = 99004
    LOG_USER_5 = 99005
    LOG_USER_6 = 99006
    LOG_USER_7 = 99007
    LOG_USER_8 = 99008
    LOG_USER_9 = 99009


# The legacy console renders port-scan incidents from these `logtype` values,
# which the old code wrote into the incident hash (see `LOG_PORT_SCAN_HOST` and
# `LOG_PORT_SCAN_NET` in the Python 2 implementation). They are incident
# labels, not event types: 5002/5003 are NMAP OS/NULL scans in modern canaries.
INCIDENT_LOGTYPE_NETWORK_PORT_SCAN: Final[int] = 5002
INCIDENT_LOGTYPE_HOST_PORT_SCAN: Final[int] = 5003

DEFAULT_LOGTYPE: Final[LogType] = LogType.LOG_BASE_MSG

#: Field defaults applied by `opencanary.logger.LoggerBase.sanitizeLog()`.
DEFAULT_EVENT_FIELDS: Final[dict[str, Any]] = {
    "src_host": "",
    "src_port": -1,
    "dst_host": "",
    "dst_port": -1,
    "logtype": int(DEFAULT_LOGTYPE),
    "logdata": {},
}

#: Canonical incident name -> legacy Redis key prefix.
INCIDENT_KEY_PREFIX: Final[dict[str, str]] = {
    "ftp.login_attempt": "incident:ftplogin:",
    "http.login_attempt": "incident:httplogin:",
    "ssh.login_attempt": "incident:sshlogin:",
    "telnet.login_attempt": "incident:telnetlogin:",
    "httpproxy.login_attempt": "incident:httpproxylogin:",
    "mysql.login_attempt": "incident:mysqllogin:",
    "mssql.login_attempt": "incident:mssqllogin:",
    "tftp.action": "incident:tftp:",
    "ntp.monlist": "incident:ntpmonlist:",
    "vnc.login_attempt": "incident:vnclogin:",
    "snmp.cmd": "incident:snmplogin:",
    "rdp.login_attempt": "incident:rdplogin:",
    "sip.login_attempt": "incident:siplogin:",
    "smb.file_open": "incident:smbfileopen:",
    "scans.host_portscan": "incident:hostportscan:",
    "scans.network_portscan": "incident:networkportscan:",
}

#: Redis keys shared with the legacy console.
KEY_INCIDENTS: Final[str] = "incidents"
KEY_LOGS: Final[str] = "logs"
KEY_DEVICE: Final[str] = "device:"
KEY_CONSOLE_SETTING_PREFIX: Final[str] = "console-setting:"
KEY_WHITELIST_IPS: Final[str] = "whitelist-ips:"
KEY_TRACK_HOST_PORT_SCAN: Final[str] = "scan:host:"
KEY_TRACK_NETWORK_PORT_SCAN: Final[str] = "scan:network:"

#: Upper bound on events rendered from a single incident, as in the legacy code.
MAX_EVENT_COUNT: Final[int] = 100

__all__ = [
    "DEFAULT_EVENT_FIELDS",
    "DEFAULT_LOGTYPE",
    "INCIDENT_KEY_PREFIX",
    "INCIDENT_LOGTYPE_HOST_PORT_SCAN",
    "INCIDENT_LOGTYPE_NETWORK_PORT_SCAN",
    "KEY_CONSOLE_SETTING_PREFIX",
    "KEY_DEVICE",
    "KEY_INCIDENTS",
    "KEY_LOGS",
    "KEY_TRACK_HOST_PORT_SCAN",
    "KEY_TRACK_NETWORK_PORT_SCAN",
    "KEY_WHITELIST_IPS",
    "MAX_EVENT_COUNT",
    "LogType",
]
