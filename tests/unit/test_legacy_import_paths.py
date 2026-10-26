"""Legacy import paths keep exporting the names they exported before the refactor."""

from __future__ import annotations

import importlib

import pytest

LEGACY_EXPORTS: dict[str, tuple[str, ...]] = {
    "opencanary_correlator.config": (
        "INCIDENT_KEY_PREFIX",
        "Settings",
        "parse_allowed_networks",
    ),
    "opencanary_correlator.core.incident": (
        "DEFAULT_LOGTYPE",
        "Incident",
        "IncidentRepository",
        "INCIDENT_TYPES",
    ),
    "opencanary_correlator.connectors.receivers": (
        "SyslogTCPReceiver",
        "SyslogUDPReceiver",
        "TCPJSONReceiver",
    ),
}


@pytest.mark.parametrize(
    ("module_name", "name"),
    [(module, name) for module, names in LEGACY_EXPORTS.items() for name in names],
)
def test_legacy_path_exports_name(module_name: str, name: str) -> None:
    module = importlib.import_module(module_name)
    assert getattr(module, name) is not None
    assert name in module.__all__


def test_legacy_names_are_the_canonical_objects() -> None:
    config = importlib.import_module("opencanary_correlator.config")
    constants = importlib.import_module("opencanary_correlator.constants")
    allowlist = importlib.import_module("opencanary_correlator.connectors.receivers._allowlist")
    incident = importlib.import_module("opencanary_correlator.core.incident")

    assert config.INCIDENT_KEY_PREFIX is constants.INCIDENT_KEY_PREFIX
    assert config.parse_allowed_networks is allowlist.parse_allowed_networks
    assert incident.DEFAULT_LOGTYPE is constants.DEFAULT_LOGTYPE
