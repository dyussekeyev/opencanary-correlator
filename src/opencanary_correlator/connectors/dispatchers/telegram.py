"""Telegram Bot API dispatcher."""

from __future__ import annotations

from typing import Any, ClassVar

from pydantic import SecretStr

from opencanary_correlator.connectors.base import IncidentLike
from opencanary_correlator.connectors.dispatchers.base import HTTPDispatcher

TELEGRAM_MAX_TEXT = 4096


class TelegramDispatcher(HTTPDispatcher):
    """Send the compact report to one Telegram chat."""

    name: ClassVar[str] = "telegram"

    def __init__(self, *, token: SecretStr | str, chat_id: str, **kwargs: Any) -> None:
        self._chat_id = chat_id
        secret = SecretStr(token) if isinstance(token, str) else token
        super().__init__(url=self._api_url(secret), **kwargs)

    @staticmethod
    def _api_url(token: SecretStr) -> str:
        return f"https://api.telegram.org/bot{token.get_secret_value()}/sendMessage"

    def build_payload(self, incident: IncidentLike) -> dict[str, Any]:
        """Telegram rejects messages longer than 4096 characters."""
        return {
            "chat_id": self._chat_id,
            "text": incident.format_report_short()[:TELEGRAM_MAX_TEXT],
            "disable_web_page_preview": True,
        }


__all__ = ["TELEGRAM_MAX_TEXT", "TelegramDispatcher"]
