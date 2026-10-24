"""Generic JSON webhook, suitable for Elastic, Wazuh or Splunk HEC shims."""

from __future__ import annotations

from typing import Any, ClassVar

from opencanary_correlator.connectors.base import IncidentLike
from opencanary_correlator.connectors.dispatchers.base import HTTPDispatcher


class WebhookDispatcher(HTTPDispatcher):
    """POST a structured incident document to an arbitrary endpoint."""

    name: ClassVar[str] = "webhook"

    def build_payload(self, incident: IncidentLike) -> dict[str, Any]:
        """Render the incident without raw `logdata` (it may hold credentials)."""
        return {
            "title": incident.format_title(),
            "text": incident.format_report(),
            "key": incident.key,
        }


__all__ = ["WebhookDispatcher"]
