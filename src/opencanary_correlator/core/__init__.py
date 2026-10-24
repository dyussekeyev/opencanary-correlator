"""Correlation core: windows, incidents, rules and the engine."""

from __future__ import annotations

from opencanary_correlator.core.engine import CorrelationEngine
from opencanary_correlator.core.incident import INCIDENT_TYPES, Incident, IncidentRepository
from opencanary_correlator.core.windows import DedupCache, DistinctSetWindow, SlidingWindow

__all__ = [
    "INCIDENT_TYPES",
    "CorrelationEngine",
    "DedupCache",
    "DistinctSetWindow",
    "Incident",
    "IncidentRepository",
    "SlidingWindow",
]
