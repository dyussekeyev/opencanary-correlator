"""Pure validation rules for :class:`opencanary_correlator.config.Settings`.

These functions hold no state and read no environment. ``Settings`` wires them
into pydantic field validators, so the rules can be reviewed and tested apart
from environment loading.
"""

from __future__ import annotations

import json
import re
from typing import Any, Final
from urllib.parse import urlparse

from pydantic import SecretStr

from opencanary_correlator.connectors.receivers._allowlist import parse_allowed_networks
from opencanary_correlator.constants import INCIDENT_KEY_PREFIX

#: Interface the probe listener binds to when nothing is configured. The wildcard
#: is deliberate: Kubernetes probes and the Docker bridge arrive from another
#: address, so a loopback default would silently break them.
LOOPBACK_HOSTS: Final[frozenset[str]] = frozenset({"localhost", "127.0.0.1", "::1"})
TELEGRAM_TOKEN_RE: Final[re.Pattern[str]] = re.compile(r"[0-9]+:[A-Za-z0-9_-]+")
DEFAULT_HEALTH_HOST: Final[str] = "0.0.0.0"  # noqa: S104 - probe endpoint defaults to every interface

#: Port for the health and `/metrics` listener. 8080 is the classic HTTP-alt
#: port and collides with the web services a honeypot imitates, so the default
#: sits in the same uncommon block as the intake ports.
DEFAULT_HEALTH_PORT: Final[int] = 15142

#: Interface the event receivers bind to when nothing is configured. Loopback
#: keeps the unauthenticated event intake off the network in the common
#: single-host deployment; remote canaries set OCC_TCP_HOST/OCC_SYSLOG_HOST.
DEFAULT_INTAKE_HOST: Final[str] = "127.0.0.1"

#: Peers allowed to read the health and metrics endpoints when nothing is configured.
DEFAULT_HEALTH_ALLOWED_IPS: Final[tuple[str, ...]] = ("127.0.0.1/32", "::1/128")

#: Upper bound for a per-incident horizon, in seconds (one week).
MAX_INCIDENT_HORIZON_SECONDS: Final[float] = 7 * 24 * 3600.0

#: Delivery channels a service message can be routed to. Kept here rather than
#: imported from `app.channels`, which imports this module's owner: a test asserts
#: the two lists agree, so a new channel cannot be forgotten in one of them.
KNOWN_CHANNEL_NAMES: Final[tuple[str, ...]] = (
    "webhook",
    "slack",
    "discord",
    "telegram",
    "smtp",
)

#: Groups of service messages an operator can switch on independently. `digest`
#: is listed for completeness; it is governed by `OCC_DIGEST_ENABLED` instead.
SERVICE_CATEGORIES: Final[tuple[str, ...]] = (
    "enrichment",
    "channels",
    "lifecycle",
    "digest",
)

#: `HH:MM` in UTC for the daily digest.
DIGEST_TIME_RE: Final[re.Pattern[str]] = re.compile(r"^([01]?\d|2[0-3]):([0-5]\d)$")


def split_comma_separated(value: Any) -> Any:
    """Split a comma-separated string, or decode a JSON array, into a list."""
    if not isinstance(value, str):
        return value
    text = value.strip()
    if not text:
        return []
    if text.startswith("["):
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return [text]
    return [item.strip() for item in text.split(",") if item.strip()]


def require_http_urls(value: list[str]) -> list[str]:
    """Accept http(s) URLs only, and plain http only for loopback targets.

    The message never echoes the URL: webhook credentials live in the path or
    the query string, and startup errors end up in stderr and in the container
    log. The position in the list is enough to fix the entry.
    """
    for index, url in enumerate(value):
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError(
                f"webhook_urls[{index}] must be an http(s) URL, got "
                f"scheme {parsed.scheme or '<none>'!r}"
            )
        # Plain http leaves the payload (incident data, sometimes tokens in
        # the URL path) readable on the wire; only loopback may use it.
        if parsed.scheme == "http" and parsed.hostname not in LOOPBACK_HOSTS:
            raise ValueError(
                f"webhook_urls[{index}] must use https unless it is loopback "
                f"(host {parsed.hostname!r})"
            )
    return value


def validate_telegram_token(value: SecretStr | None) -> SecretStr | None:
    """Telegram tokens are ``<bot id>:<secret>``; reject anything else up front.

    The token is embedded in the request URL, so a malformed value must never
    reach the dispatcher.
    """
    if value is not None and not TELEGRAM_TOKEN_RE.fullmatch(value.get_secret_value()):
        raise ValueError("telegram_token must look like '<digits>:<secret>'")
    return value


def validate_allowed_ips(value: list[str]) -> list[str]:
    """Fail at startup on a bad entry instead of silently widening the allowlist."""
    parse_allowed_networks(value)
    return value


def health_allowlist_or_loopback(value: list[str]) -> list[str]:
    """The health endpoint must never be open by accident: empty means loopback."""
    return value or list(DEFAULT_HEALTH_ALLOWED_IPS)


def decode_incident_horizons(value: Any) -> Any:
    """Decode the per-incident horizon map from a JSON string or an empty value."""
    if value is None or value == "":
        return {}
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError as exc:
            raise ValueError("incident_horizons must be a JSON object") from exc
    return value


def validate_incident_horizons(value: dict[str, float]) -> dict[str, float]:
    """Only known incident names, each with a horizon within the allowed range."""
    unknown = sorted(set(value) - set(INCIDENT_KEY_PREFIX))
    if unknown:
        raise ValueError("unknown incident names in incident_horizons: " + ", ".join(unknown))
    for incident_name, seconds in value.items():
        if not 0 <= seconds <= MAX_INCIDENT_HORIZON_SECONDS:
            raise ValueError(
                f"{incident_name} horizon must be between 0 and "
                f"{MAX_INCIDENT_HORIZON_SECONDS:.0f} seconds"
            )
    return value


def require_redis_scheme(value: str) -> str:
    """Only the three supported Redis URL schemes are accepted."""
    if not value.startswith(("redis://", "rediss://", "unix://")):
        raise ValueError("redis_url must start with redis://, rediss:// or unix://")
    return value


def normalise_log_level(value: Any) -> Any:
    """Log levels are case-insensitive and accept the customary short aliases.

    ``WARN`` and ``FATAL`` are what operators and existing cron wrappers type;
    an unknown name is passed through so pydantic reports the allowed set.
    """
    if not isinstance(value, str):
        return value
    text = value.strip().upper()
    return {"WARN": "WARNING", "FATAL": "CRITICAL"}.get(text, text)


def normalise_log_file(value: Any) -> Any:
    """Treat a blank path as "no log file" instead of the working directory.

    An empty ``OCC_LOG_FILE`` is the documented way to keep stderr-only output,
    and `Path("")` would otherwise point at the current directory.
    """
    if value is None:
        return None
    if isinstance(value, str):
        text = value.strip()
        return text or None
    return value


def normalise_alert_detail(value: Any) -> Any:
    """Alert detail levels are case-insensitive and accept short aliases.

    Unknown values are passed through so pydantic reports the allowed set; a
    silently coerced level would change what an operator sees in chat.
    """
    if not isinstance(value, str):
        return value
    text = value.strip().lower()
    aliases = {"brief": "minimal", "short": "minimal", "full": "detailed", "verbose": "detailed"}
    return aliases.get(text, text)


def require_slack_endpoints(enabled: bool, webhooks: list[str]) -> None:
    """Reject a Slack channel that is switched on but has nowhere to send.

    ``OCC_SLACK_ENABLED=true`` with an empty ``OCC_SLACK_WEBHOOKS`` was a silent
    no-op: the flag promised a channel that never existed, and nothing in the
    logs said so. Failing at startup turns the contradiction into a message the
    operator can act on. The flag defaults to false now, so simply configuring a
    webhook is not enough on its own — see ``slack_configured_but_disabled``.
    """
    if enabled and not webhooks:
        raise ValueError(
            "slack_enabled requires at least one URL in slack_webhooks; "
            "set OCC_SLACK_WEBHOOKS or unset OCC_SLACK_ENABLED"
        )


def slack_configured_but_disabled(enabled: bool, webhooks: list[str]) -> bool:
    """True when webhooks exist but the kill switch is off.

    The other half of the same mistake: a webhook pasted into ``.env`` next to a
    forgotten ``OCC_SLACK_ENABLED=false``. Startup logs a warning for it instead
    of failing, because disabling a channel on purpose is legitimate.
    """
    return bool(webhooks) and not enabled


def validate_service_channels(value: list[str]) -> list[str]:
    """Reject a service-message channel name the correlator does not know.

    A misspelled name would otherwise mean "send to nobody": the setting would
    look configured and the deployment would silently report nothing, which is
    the exact blind spot service messages exist to remove.
    """
    normalised = [name.strip().lower() for name in value if name.strip()]
    unknown = sorted(set(normalised) - set(KNOWN_CHANNEL_NAMES))
    if unknown:
        raise ValueError(
            "unknown service_channels entries: "
            + ", ".join(unknown)
            + f" (expected any of {', '.join(KNOWN_CHANNEL_NAMES)})"
        )
    return normalised


def validate_service_categories(value: list[str]) -> list[str]:
    """Reject a service-message category that nothing would ever match."""
    normalised = [name.strip().lower() for name in value if name.strip()]
    unknown = sorted(set(normalised) - set(SERVICE_CATEGORIES))
    if unknown:
        raise ValueError(
            "unknown service_categories entries: "
            + ", ".join(unknown)
            + f" (expected any of {', '.join(SERVICE_CATEGORIES)})"
        )
    return normalised


def validate_digest_time(value: str) -> str:
    """Accept 24-hour `HH:MM` in UTC, zero-padded, and nothing else.

    A malformed time would otherwise be parsed leniently or ignored, and the
    digest would run at a time the operator did not ask for - or never.
    """
    text = value.strip()
    match = DIGEST_TIME_RE.match(text)
    if match is None:
        raise ValueError("digest_time must be HH:MM in UTC, e.g. 03:00")
    return f"{int(match.group(1)):02d}:{match.group(2)}"


def normalise_service_severity(value: Any) -> Any:
    """Severity levels are case-insensitive and accept the usual short aliases."""
    if not isinstance(value, str):
        return value
    text = value.strip().lower()
    return {"warn": "warning", "crit": "critical", "fatal": "critical"}.get(text, text)


def require_email_address(value: str) -> str:
    """Minimal structural check: an address with a local part and a domain."""
    if "@" not in value or value.startswith("@") or value.endswith("@"):
        raise ValueError("smtp_from must be an email address")
    return value


def normalise_health_host(value: Any) -> Any:
    """Trim the configured bind address; an empty value means "all interfaces"."""
    if value is None:
        return DEFAULT_HEALTH_HOST
    text = str(value).strip()
    return text or DEFAULT_HEALTH_HOST


def disable_health_port(value: Any) -> Any:
    """Treat any numeric zero and an empty value as "no health endpoint"."""
    if value is None:
        return None
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            value = int(text)
        except ValueError:
            return value
    return None if value == 0 else value


__all__ = [
    "DEFAULT_HEALTH_ALLOWED_IPS",
    "DEFAULT_HEALTH_HOST",
    "DEFAULT_HEALTH_PORT",
    "DEFAULT_INTAKE_HOST",
    "DIGEST_TIME_RE",
    "KNOWN_CHANNEL_NAMES",
    "LOOPBACK_HOSTS",
    "MAX_INCIDENT_HORIZON_SECONDS",
    "SERVICE_CATEGORIES",
    "TELEGRAM_TOKEN_RE",
    "decode_incident_horizons",
    "disable_health_port",
    "health_allowlist_or_loopback",
    "normalise_alert_detail",
    "normalise_health_host",
    "normalise_log_file",
    "normalise_log_level",
    "normalise_service_severity",
    "require_email_address",
    "require_http_urls",
    "require_redis_scheme",
    "require_slack_endpoints",
    "slack_configured_but_disabled",
    "split_comma_separated",
    "validate_allowed_ips",
    "validate_digest_time",
    "validate_incident_horizons",
    "validate_service_categories",
    "validate_service_channels",
    "validate_telegram_token",
]
