"""Incident rendering: titles, the full report and the legacy short line."""

from __future__ import annotations

import json
import logging
from typing import Any

from opencanary_correlator.core.incident import (
    IncidentHTTPRequest,
    IncidentNetworkPortScan,
    IncidentSMBFileOpen,
)
from tests.unit.incident_factories import make_incident


def test_title_and_short_report_match_the_legacy_text() -> None:
    incident = make_incident()

    assert incident.format_title() == "FTP Login Attempt by 10.0.0.5 on canary-1 (10.0.0.2)"
    assert incident.format_report_short() == (
        "Canary Incident: FTP Login Attempt. Source 10.0.0.5. Target canary-1 (10.0.0.2)."
    )


def test_full_report_matches_the_legacy_layout() -> None:
    report = make_incident().format_report()

    assert report.startswith("\n" + "=" * 70)
    assert "  Incident: FTP Login Attempt" in report
    assert "  Time    : 2014-12-19 13:50:29 (UTC)" in report
    assert "  Source  : 10.0.0.5" in report
    assert "  Target  : 10.0.0.2 (id canary-1)" in report
    assert "EXTRA" not in report


def test_smb_report_includes_file_and_user() -> None:
    incident = make_incident(
        IncidentSMBFileOpen,
        logdata=json.dumps([{"FILENAME": "payroll.xlsx", "USER": "admin"}]),
    )

    assert "  File    : payroll.xlsx" in incident.format_report()
    assert "  User    : admin" in incident.format_report()
    assert 'File "payroll.xlsx", user "admin"' in incident.format_report_short()


def test_http_request_report_shows_the_request_line() -> None:
    incident = make_incident(
        IncidentHTTPRequest,
        logtype=3000,
        dst_port=80,
        logdata=json.dumps(
            [{"METHOD": "GET", "PATH": "/admin", "HOST": "canary-1", "USERAGENT": "curl/8.4.0"}]
        ),
    )

    report = incident.format_report()

    assert "  Incident: HTTP Request" in report
    assert "  Method  : GET" in report
    assert "  Path    : /admin" in report
    assert "  Host    : canary-1" in report
    assert "  Agent   : curl/8.4.0" in report
    assert 'GET "/admin" on canary-1' in incident.format_report_short()


def test_http_request_report_without_logdata_falls_back_to_the_base_report() -> None:
    incident = make_incident(IncidentHTTPRequest, logtype=3000, logdata=None)

    assert "  Incident: HTTP Request" in incident.format_report()
    assert "  Path" not in incident.format_report()
    assert incident.format_report_short() == (
        "Canary Incident: HTTP Request. Source 10.0.0.5. Target canary-1 (10.0.0.2)."
    )


def test_smb_report_without_logdata_falls_back_to_the_base_report() -> None:
    incident = make_incident(IncidentSMBFileOpen, logdata=None)

    assert "Shared File Opened" in incident.format_report()
    assert "EXTRA" not in incident.format_report()


def test_smb_failure_never_logs_the_stored_payload(caplog: Any) -> None:
    """The fallback branch used to log `logdata` raw, which can hold a password."""
    incident = make_incident(IncidentSMBFileOpen, logdata='{"PASSWORD": "hunter2"')

    with caplog.at_level(logging.ERROR, logger="opencanary_correlator.core.incident"):
        report = incident.format_report()

    assert "Shared File Opened" in report
    assert "hunter2" not in caplog.text
    assert incident.key in caplog.text


def test_network_scan_report_lists_targets() -> None:
    incident = make_incident(
        IncidentNetworkPortScan,
        logdata=json.dumps(["10.0.0.2", "10.0.0.3"]),
        logtype=5002,
        dst_port=22,
    )

    report = incident.format_report()

    assert "  Port    : 22" in report
    assert "  Targets : 10.0.0.2, 10.0.0.3" in report
