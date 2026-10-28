"""Delivery channels: the single table that lists and builds them.

`--check-config` and startup both read `CHANNEL_SPECS`, so a channel can no
longer be advertised by one and silently missing from the other.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from functools import partial
from typing import Final, cast

from pydantic import SecretStr

from opencanary_correlator.config import Settings
from opencanary_correlator.connectors.base import BaseDispatcher
from opencanary_correlator.connectors.dispatchers import (
    CircuitBreaker,
    DiscordDispatcher,
    SlackDispatcher,
    SmtpDispatcher,
    TelegramDispatcher,
    WebhookDispatcher,
    breaker_name,
)
from opencanary_correlator.storage.redis_store import RedisStore

_logger = logging.getLogger(__name__)

#: Builds the breaker that guards one endpoint of one channel.
BreakerFactory = Callable[[str], CircuitBreaker]


@dataclass(frozen=True, slots=True)
class ChannelSpec:
    """One delivery channel: how many it fans out to and how each is built.

    ``targets`` is what the channel would deliver to if it were enabled — a URL
    per webhook, a chat id per Telegram chat, a single placeholder for SMTP.
    That is exactly the fan-out `--check-config` reports, so the count and the
    dispatchers come from one description.
    """

    name: str
    enabled: Callable[[Settings], bool]
    targets: Callable[[Settings], Sequence[str]]
    detail: Callable[[Settings], str]
    build: Callable[[Settings, str, BreakerFactory], BaseDispatcher]
    #: Logged when the channel has targets but the switch is off.
    disabled_warning: str | None = None
    #: True when the target string carries the credential itself (a webhook URL).
    target_is_secret: bool = False


def _build_webhook(settings: Settings, target: str, breaker: BreakerFactory) -> BaseDispatcher:
    return WebhookDispatcher(
        url=target,
        timeout=settings.dispatch_timeout,
        breaker=breaker(target),
        detail=settings.webhook_detail,
    )


def _build_slack(settings: Settings, target: str, breaker: BreakerFactory) -> BaseDispatcher:
    return SlackDispatcher(
        url=target,
        timeout=settings.dispatch_timeout,
        breaker=breaker(target),
        detail=settings.slack_detail,
    )


def _build_discord(settings: Settings, target: str, breaker: BreakerFactory) -> BaseDispatcher:
    return DiscordDispatcher(
        url=target,
        timeout=settings.dispatch_timeout,
        breaker=breaker(target),
        detail=settings.discord_detail,
    )


def _build_telegram(settings: Settings, target: str, breaker: BreakerFactory) -> BaseDispatcher:
    # `ChannelSpec.enabled` is what keeps the token non-None here.
    token = cast(SecretStr, settings.telegram_token)
    return TelegramDispatcher(
        token=token,
        chat_id=target,
        detail=settings.telegram_detail,
        timeout=settings.dispatch_timeout,
        breaker=breaker(target),
    )


def _build_smtp(settings: Settings, _target: str, _breaker: BreakerFactory) -> BaseDispatcher:
    # One SMTP dispatcher for the configured recipient list, so the target is a
    # placeholder and the breaker plays no part (a relay failure is retried).
    return SmtpDispatcher(
        host=cast(str, settings.smtp_host),
        port=settings.smtp_port,
        sender=settings.smtp_from,
        recipients=settings.smtp_to,
        detail=settings.smtp_detail,
        username=settings.smtp_username,
        password=settings.smtp_password,
        start_tls=settings.smtp_starttls,
        use_tls=settings.smtp_use_tls,
        timeout=settings.dispatch_timeout,
    )


#: Every delivery channel, in the order they appear in a description and a build.
CHANNEL_SPECS: Final[tuple[ChannelSpec, ...]] = (
    ChannelSpec(
        name="webhook",
        enabled=lambda _settings: True,
        targets=lambda settings: tuple(settings.webhook_urls),
        detail=lambda settings: settings.webhook_detail,
        build=_build_webhook,
        target_is_secret=True,
    ),
    ChannelSpec(
        name="slack",
        enabled=lambda settings: settings.slack_enabled,
        targets=lambda settings: tuple(settings.slack_webhooks),
        detail=lambda settings: settings.slack_detail,
        build=_build_slack,
        # The opposite of the startup error: a webhook with the switch off would
        # otherwise be ignored without a word.
        disabled_warning=(
            "OCC_SLACK_WEBHOOKS is set but OCC_SLACK_ENABLED is false: Slack alerts are disabled"
        ),
        target_is_secret=True,
    ),
    ChannelSpec(
        name="discord",
        enabled=lambda _settings: True,
        targets=lambda settings: tuple(settings.discord_webhooks),
        detail=lambda settings: settings.discord_detail,
        build=_build_discord,
        target_is_secret=True,
    ),
    ChannelSpec(
        name="telegram",
        enabled=lambda settings: settings.telegram_token is not None,
        targets=lambda settings: tuple(settings.telegram_chat_ids),
        detail=lambda settings: settings.telegram_detail,
        build=_build_telegram,
    ),
    ChannelSpec(
        name="smtp",
        enabled=lambda settings: bool(
            settings.smtp_enabled and settings.smtp_host and settings.smtp_to
        ),
        targets=lambda _settings: ("smtp",),
        detail=lambda settings: settings.smtp_detail,
        build=_build_smtp,
    ),
)


def channel_names(settings: Settings) -> list[str]:
    """Names of the dispatchers that the configuration would enable."""
    return [
        spec.name
        for spec in CHANNEL_SPECS
        if spec.enabled(settings)
        for _ in spec.targets(settings)
    ]


def build_dispatchers(settings: Settings, store: RedisStore) -> list[BaseDispatcher]:
    """Instantiate every dispatcher enabled by the configuration."""
    dispatchers: list[BaseDispatcher] = []
    for spec in CHANNEL_SPECS:
        targets = spec.targets(settings)
        if not spec.enabled(settings):
            if targets and spec.disabled_warning:
                _logger.warning(spec.disabled_warning)
            continue
        # One dispatcher per target, each guarded by its own circuit breaker.
        for target in targets:
            dispatchers.append(
                spec.build(settings, target, partial(_breaker_for, store, spec.name))
            )
    return dispatchers


def _breaker_for(store: RedisStore, channel: str, endpoint: str) -> CircuitBreaker:
    """Breaker shared by every replica for one concrete endpoint."""
    return CircuitBreaker(store, breaker_name(channel, endpoint))


__all__ = [
    "CHANNEL_SPECS",
    "BreakerFactory",
    "ChannelSpec",
    "build_dispatchers",
    "channel_names",
]
