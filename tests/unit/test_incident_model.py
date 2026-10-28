"""Incident models: construction, stored fields and the registry."""

from __future__ import annotations

from opencanary_correlator.core.incident import IncidentFTPLogin, IncidentHostPortScan
from opencanary_correlator.enrichment.models import Enrichment, GeoInfo
from tests.unit.incident_factories import make_incident


def test_enrichment_is_transient_and_never_stored() -> None:
    """The engine attaches it just before dispatch; Redis must not grow a field."""
    incident = make_incident(
        IncidentFTPLogin,
        enrichment=Enrichment(geo=GeoInfo(country_code="NL", country="Netherlands")),
    )

    fields = incident.to_fields()
    rebuilt = IncidentFTPLogin.from_fields(incident.key, fields)

    assert "enrichment" not in fields
    assert rebuilt.enrichment is None


def test_incident_classes_are_registered() -> None:
    from opencanary_correlator.core.incident import INCIDENT_TYPES

    assert set(INCIDENT_TYPES) == {
        "ftp.login_attempt",
        "http.login_attempt",
        "http.request",
        "ssh.login_attempt",
        "telnet.login_attempt",
        "httpproxy.login_attempt",
        "mysql.login_attempt",
        "mssql.login_attempt",
        "tftp.action",
        "ntp.monlist",
        "vnc.login_attempt",
        "snmp.cmd",
        "rdp.login_attempt",
        "sip.login_attempt",
        "smb.file_open",
        "scans.host_portscan",
        "scans.network_portscan",
    }
    assert INCIDENT_TYPES["scans.host_portscan"] is IncidentHostPortScan
