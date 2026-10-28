"""Shared incident factories for the incident tests.

Not a `test_*.py` file, so pytest never collects it: it holds only the helper the
model, repository and report tests build their fixtures with, which is why it
lives here instead of in one of them importing another test module.
"""

from __future__ import annotations

import json
from typing import Any

from opencanary_correlator.core.incident import IncidentFTPLogin


def make_incident(incident_cls: Any = IncidentFTPLogin, **overrides: Any) -> Any:
    """Build a persisted-looking incident with stable defaults."""
    params = {
        "key": "incident:ftplogin:10.0.0.5:1418997029",
        "node_id": "canary-1",
        "src_host": "10.0.0.5",
        "src_port": 40000,
        "dst_host": "10.0.0.2",
        "dst_port": 21,
        "logtype": 2000,
        "created": 1418997029,
        "events_list": "1418997029",
        "events_count": 1,
        "logdata": json.dumps([{"USERNAME": "admin"}]),
    }
    params.update(overrides)
    return incident_cls(**params)


__all__ = ["make_incident"]
