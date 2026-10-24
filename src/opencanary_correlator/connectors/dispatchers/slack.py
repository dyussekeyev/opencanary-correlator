"""Slack incoming-webhook dispatcher."""

from __future__ import annotations

from typing import Any, ClassVar

from opencanary_correlator.connectors.base import IncidentLike
from opencanary_correlator.connectors.dispatchers.base import HTTPDispatcher


class SlackDispatcher(HTTPDispatcher):
    """Deliver the compact report to a Slack webhook, as the legacy code did."""

    name: ClassVar[str] = "slack"

    def build_payload(self, incident: IncidentLike) -> dict[str, Any]:
        """Slack accepts a simple `text` field for plain-message webhooks."""
        return {"text": incident.format_report_short()}


__all__ = ["SlackDispatcher"]
