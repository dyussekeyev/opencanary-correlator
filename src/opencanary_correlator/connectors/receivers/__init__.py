"""Concrete input receivers."""

from __future__ import annotations

from opencanary_correlator.connectors.receivers.syslog import (
    SyslogTCPReceiver,
    SyslogUDPReceiver,
)
from opencanary_correlator.connectors.receivers.tcp_json import TCPJSONReceiver

__all__ = ["SyslogTCPReceiver", "SyslogUDPReceiver", "TCPJSONReceiver"]
