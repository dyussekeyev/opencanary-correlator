"""Slack incoming-webhook dispatcher."""

from __future__ import annotations

from typing import Any, ClassVar

from opencanary_correlator.connectors.base import IncidentLike
from opencanary_correlator.connectors.dispatchers.alert_text import (
    AlertDetail,
    render_alert,
)
from opencanary_correlator.connectors.dispatchers.base import HTTPDispatcher


class SlackDispatcher(HTTPDispatcher):
    """Deliver the incident report to a Slack webhook.

    Slack renders ``*bold*`` (mrkdwn) in the ``text`` field, which the
    ``standard`` and ``detailed`` layouts use; ``minimal`` keeps the legacy
    compact line.
    """

    name: ClassVar[str] = "slack"

    def __init__(self, *, detail: AlertDetail = "standard", **kwargs: Any) -> None:
        self._detail: AlertDetail = detail
        super().__init__(**kwargs)

    def build_payload(self, incident: IncidentLike) -> dict[str, Any]:
        """Slack accepts a simple `text` field for plain-message webhooks."""
        return {"text": render_alert(incident, detail=self._detail, flavor="slack")}


__all__ = ["SlackDispatcher"]
