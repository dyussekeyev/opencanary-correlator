"""Fixtures shared by the correlation unit tests."""

from __future__ import annotations

import io
from typing import Any

import pytest

from opencanary_correlator.audit import AuditLogger
from opencanary_correlator.core.incident import IncidentRepository

START_TIME = 1_700_000_000.0


class FakeClock:
    """Controllable monotonic clock for deterministic window tests."""

    def __init__(self, now: float = START_TIME) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock() -> FakeClock:
    """Clock starting at a fixed epoch."""
    return FakeClock()


@pytest.fixture
def audit_stream() -> io.StringIO:
    """Capture audit output."""
    return io.StringIO()


@pytest.fixture
def audit(audit_stream: io.StringIO) -> AuditLogger:
    """Audit logger writing into the captured stream."""
    return AuditLogger("correlator", stream=audit_stream)


@pytest.fixture
def repository(store: Any, settings_factory: Any, audit: Any, clock: Any) -> IncidentRepository:
    """Incident repository using the fake store and clock."""
    return IncidentRepository(store, settings_factory(), audit, clock=clock)
