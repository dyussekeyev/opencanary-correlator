"""Fixtures shared by the socket-level receiver tests."""

from __future__ import annotations

import io

import pytest
from helpers import CollectingSink

from opencanary_correlator.audit import AuditLogger


@pytest.fixture
def sink() -> CollectingSink:
    """Collect events delivered by a receiver."""
    return CollectingSink()


@pytest.fixture
def audit_stream() -> io.StringIO:
    """Capture the audit trail as JSON lines."""
    return io.StringIO()


@pytest.fixture
def audit(audit_stream: io.StringIO) -> AuditLogger:
    """Audit logger writing into the captured stream."""
    return AuditLogger("test_receiver", stream=audit_stream)
