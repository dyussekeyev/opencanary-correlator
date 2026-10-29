"""Discord webhook dispatcher.

Discord limits message `content` to 2000 characters and embed descriptions to
4096, so long reports are sent as an embed.
"""

from __future__ import annotations

from collections.abc import Sequence
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

DISCORD_MAX_CONTENT = 2000
DISCORD_MAX_EMBED_DESCRIPTION = 4096
DISCORD_MAX_TITLE = 256
DISCORD_ALERT_COLOR = 15_158_332  # #E74C3C


class DiscordDispatcher(HTTPDispatcher):
    """Deliver incidents to a Discord channel webhook."""

    name: ClassVar[str] = "discord"

    def __init__(
        self,
        *,
        detail: AlertDetail = "standard",
        expected_status: Sequence[int] = (200, 204),
        **kwargs: Any,
    ) -> None:
        """Discord answers `204 No Content` for a successful webhook execution."""
        self._detail: AlertDetail = detail
        super().__init__(expected_status=expected_status, **kwargs)

    def build_service_payload(self, message: ServiceMessage) -> dict[str, Any]:
        """Service messages are short, so they fit in `content`."""
        return {
            "content": render_service_message(
                message, flavor="discord", max_length=DISCORD_MAX_CONTENT
            )
        }

    def build_payload(self, incident: IncidentLike) -> dict[str, Any]:
        """Use `content` when it fits, otherwise a single embed."""
        body = render_alert(incident, detail=self._detail, flavor="discord")
        if len(body) <= DISCORD_MAX_CONTENT:
            return {"content": body}
        # The embed has more room, so ``minimal`` falls back to the legacy full
        # report instead of the short line that did not fit.
        description = incident.format_report() if self._detail == "minimal" else body
        return {
            "embeds": [
                {
                    "title": clip(incident.format_title(), DISCORD_MAX_TITLE),
                    "description": clip(description, DISCORD_MAX_EMBED_DESCRIPTION),
                    "color": DISCORD_ALERT_COLOR,
                }
            ]
        }


__all__ = [
    "DISCORD_ALERT_COLOR",
    "DISCORD_MAX_CONTENT",
    "DISCORD_MAX_EMBED_DESCRIPTION",
    "DISCORD_MAX_TITLE",
    "DiscordDispatcher",
]
