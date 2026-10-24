"""Discord webhook dispatcher.

Discord limits message `content` to 2000 characters and embed descriptions to
4096, so long reports are sent as an embed.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, ClassVar

from opencanary_correlator.connectors.base import IncidentLike
from opencanary_correlator.connectors.dispatchers.base import HTTPDispatcher

DISCORD_MAX_CONTENT = 2000
DISCORD_MAX_EMBED_DESCRIPTION = 4096
DISCORD_ALERT_COLOR = 15_158_332  # #E74C3C


class DiscordDispatcher(HTTPDispatcher):
    """Deliver incidents to a Discord channel webhook."""

    name: ClassVar[str] = "discord"

    def __init__(
        self,
        *,
        expected_status: Sequence[int] = (200, 204),
        **kwargs: Any,
    ) -> None:
        """Discord answers `204 No Content` for a successful webhook execution."""
        super().__init__(expected_status=expected_status, **kwargs)

    def build_payload(self, incident: IncidentLike) -> dict[str, Any]:
        """Use `content` when it fits, otherwise a single embed."""
        short = incident.format_report_short()
        if len(short) <= DISCORD_MAX_CONTENT:
            return {"content": short}
        return {
            "embeds": [
                {
                    "title": incident.format_title()[:256],
                    "description": incident.format_report()[:DISCORD_MAX_EMBED_DESCRIPTION],
                    "color": DISCORD_ALERT_COLOR,
                }
            ]
        }


__all__ = [
    "DISCORD_ALERT_COLOR",
    "DISCORD_MAX_CONTENT",
    "DISCORD_MAX_EMBED_DESCRIPTION",
    "DiscordDispatcher",
]
