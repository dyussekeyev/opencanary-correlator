"""Telegram Bot API dispatcher."""

from __future__ import annotations

from typing import Any, ClassVar

from pydantic import SecretStr

from opencanary_correlator.connectors.base import IncidentLike
from opencanary_correlator.connectors.dispatchers.alert_text import (
    AlertDetail,
    render_alert,
)
from opencanary_correlator.connectors.dispatchers.base import HTTPDispatcher

TELEGRAM_MAX_TEXT = 4096


class TelegramDispatcher(HTTPDispatcher):
    """Send the incident report to one Telegram chat.

    ``detail`` selects the message layout: ``minimal`` keeps the legacy single
    line, ``standard`` and ``detailed`` send the multiline MarkdownV2 report.
    """

    name: ClassVar[str] = "telegram"

    def __init__(
        self,
        *,
        token: SecretStr | str,
        chat_id: str,
        detail: AlertDetail = "standard",
        **kwargs: Any,
    ) -> None:
        self._chat_id = chat_id
        self._detail: AlertDetail = detail
        secret = SecretStr(token) if isinstance(token, str) else token
        super().__init__(url=self._api_url(secret), **kwargs)

    @staticmethod
    def _api_url(token: SecretStr) -> str:
        return f"https://api.telegram.org/bot{token.get_secret_value()}/sendMessage"

    def build_payload(self, incident: IncidentLike) -> dict[str, Any]:
        """Telegram rejects messages longer than 4096 characters."""
        payload: dict[str, Any] = {
            "chat_id": self._chat_id,
            "text": render_alert(
                incident,
                detail=self._detail,
                flavor="telegram",
                max_length=TELEGRAM_MAX_TEXT,
            ),
            "disable_web_page_preview": True,
        }
        if self._detail != "minimal":
            # Only the rendered layout is escaped for MarkdownV2; the legacy
            # line is sent unparsed, exactly as before.
            payload["parse_mode"] = "MarkdownV2"
        return payload


__all__ = ["TELEGRAM_MAX_TEXT", "TelegramDispatcher"]
