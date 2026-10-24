"""Concrete alert dispatchers."""

from __future__ import annotations

from opencanary_correlator.connectors.dispatchers.base import (
    CircuitBreaker,
    HTTPDispatcher,
    RetryPolicy,
)
from opencanary_correlator.connectors.dispatchers.discord import DiscordDispatcher
from opencanary_correlator.connectors.dispatchers.slack import SlackDispatcher
from opencanary_correlator.connectors.dispatchers.smtp import SmtpDispatcher
from opencanary_correlator.connectors.dispatchers.telegram import TelegramDispatcher
from opencanary_correlator.connectors.dispatchers.webhook import WebhookDispatcher

__all__ = [
    "CircuitBreaker",
    "DiscordDispatcher",
    "HTTPDispatcher",
    "RetryPolicy",
    "SlackDispatcher",
    "SmtpDispatcher",
    "TelegramDispatcher",
    "WebhookDispatcher",
]
