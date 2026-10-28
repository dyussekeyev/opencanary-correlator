"""Generic JSON webhook, suitable for Elastic, Wazuh or Splunk HEC shims."""

from __future__ import annotations

from typing import Any, ClassVar

from opencanary_correlator.connectors.base import IncidentLike
from opencanary_correlator.connectors.dispatchers.alert_text import (
    AlertDetail,
    render_alert,
)
from opencanary_correlator.connectors.dispatchers.base import HTTPDispatcher


class WebhookDispatcher(HTTPDispatcher):
    """POST a structured incident document to an arbitrary endpoint.

    The default ``minimal`` level keeps the legacy ``text`` field byte-identical
    so SIEM parsers are unaffected; ``standard`` and ``detailed`` send the rich
    plain-text layout instead.
    """

    name: ClassVar[str] = "webhook"

    def __init__(self, *, detail: AlertDetail = "minimal", **kwargs: Any) -> None:
        self._detail: AlertDetail = detail
        super().__init__(**kwargs)

    def build_payload(self, incident: IncidentLike) -> dict[str, Any]:
        """Render the incident without raw `logdata` (it may hold credentials)."""
        text = (
            incident.format_report()
            if self._detail == "minimal"
            else render_alert(incident, detail=self._detail, flavor="plain")
        )
        return {
            "title": incident.format_title(),
            "text": text,
            "key": incident.key,
        }


__all__ = ["WebhookDispatcher"]
