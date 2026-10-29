"""Slack incoming-webhook dispatcher."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from opencanary_correlator.connectors.base import IncidentLike
from opencanary_correlator.connectors.dispatchers.alert_text import (
    AlertDetail,
    clip,
    render_alert,
    render_service_message,
)
from opencanary_correlator.connectors.dispatchers.base import HTTPDispatcher

if TYPE_CHECKING:  # pragma: no cover - typing only
    from opencanary_correlator.core.service_messages import ServiceMessage

SLACK_MAX_TEXT = 39_000


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

    def build_service_payload(self, message: ServiceMessage) -> dict[str, Any]:
        """A service message is a human-readable line, so Slack carries it as-is."""
        return {"text": render_service_message(message, flavor="slack")}

    def build_notice_payload(self, message: str) -> dict[str, Any]:
        """A budget summary is a message for people, so Slack carries it."""
        return {"text": clip(message, SLACK_MAX_TEXT)}


__all__ = ["SLACK_MAX_TEXT", "SlackDispatcher"]
