"""Pure validation rules for :class:`opencanary_correlator.config.Settings`.

These functions hold no state and read no environment. ``Settings`` wires them
into pydantic field validators, so the rules can be reviewed and tested apart
from environment loading.
"""

from __future__ import annotations

import ipaddress
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
    "ingestion",
    "canary",
    "lifecycle",
    "digest",
)

#: `HH:MM` in UTC for the daily digest.
DIGEST_TIME_RE: Final[re.Pattern[str]] = re.compile(r"^([01]?\d|2[0-3]):([0-5]\d)$")

#: Longest accepted Samba audit action name. Samba writes bare verbs (`openat`,
#: `create_file`); anything much longer is a typo or a payload.
MAX_SMB_ACTION_LENGTH: Final[int] = 64

#: How an OpenCTI indicator is created: never, only when the lookup found
#: nothing, or on every alert (create-or-update, never a duplicate).
OPENCTI_CREATE_MODES: Final[tuple[str, ...]] = ("off", "missing", "always")

#: MISP publication is either a human-reviewed draft or an explicit auto-publish.
MISP_PUBLISH_MODES: Final[tuple[str, ...]] = ("draft", "auto")
MISP_TLP_LEVELS: Final[tuple[str, ...]] = ("clear", "green", "amber", "amber+strict", "red")
MISP_PAP_LEVELS: Final[tuple[str, ...]] = ("clear", "green", "amber", "red")
MAX_MISP_TAG_LENGTH: Final[int] = 255
MAX_MISP_NAMESPACE_LENGTH: Final[int] = 64

#: Auth-service incident types that may carry `to_ids=true` once the daily
#: observation count and the warninglist gate both pass. HTTP requests, scans,
#: SMB, SNMP, NTP and TFTP deliberately stay out of the initial allowlist.
DEFAULT_MISP_TO_IDS_TYPES: Final[tuple[str, ...]] = (
    "ftp.login_attempt",
    "http.login_attempt",
    "ssh.login_attempt",
    "telnet.login_attempt",
    "httpproxy.login_attempt",
    "mysql.login_attempt",
    "mssql.login_attempt",
    "vnc.login_attempt",
    "rdp.login_attempt",
    "sip.login_attempt",
)

#: Longest accepted OpenCTI label. STIX has no hard limit; a configuration is
#: not a data feed, and a label is copied into every indicator created.
MAX_OPENCTI_LABEL_LENGTH: Final[int] = 64

#: Longest accepted honeypot identity (an IP literal or DNS name).
MAX_NOTIFICATION_REDACT_VALUE_LENGTH: Final[int] = 253

#: How many honeypot identities one deployment may protect. A list is a small
#: inventory of the operator's own hosts, not a blocklist.
MAX_NOTIFICATION_REDACT_VALUES: Final[int] = 100

_DNS_LABEL_RE: Final[re.Pattern[str]] = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def normalise_notification_redact_values(value: list[str]) -> list[str]:
    """Normalise the honeypot identities whose names must not leave the estate.

    Values are IP literals (v4 or v6) or DNS names. They are compared against
    outgoing notification text, so they are canonicalised here: IPs through
    `ipaddress` (which also folds IPv6 shorthand), DNS names to lower case, and
    duplicates removed. Anything else is rejected instead of being treated as a
    partial match, because a typo in a privacy control must not fail silently.
    """
    if len(value) > MAX_NOTIFICATION_REDACT_VALUES:
        raise ValueError(
            f"notification_redact_values accepts at most {MAX_NOTIFICATION_REDACT_VALUES} entries"
        )
    unique: dict[str, None] = {}
    for raw in value:
        candidate = raw.strip().rstrip(".")
        if not candidate:
            continue
        if len(candidate) > MAX_NOTIFICATION_REDACT_VALUE_LENGTH:
            raise ValueError(
                "notification_redact_values entry exceeds "
                f"{MAX_NOTIFICATION_REDACT_VALUE_LENGTH} characters"
            )
        if any(ord(character) < 33 or ord(character) == 127 for character in candidate):
            raise ValueError(
                "notification_redact_values must not contain whitespace or control characters"
            )
        try:
            unique.setdefault(str(ipaddress.ip_address(candidate)), None)
            continue
        except ValueError:
            pass
        lowered = candidate.lower()
        labels = lowered.split(".")
        if all(label.isdigit() for label in labels):
            # A dotted all-numeric value is a malformed IP, not a DNS name.
            raise ValueError("notification_redact_values entries must be IP addresses or DNS names")
        if not all(_DNS_LABEL_RE.match(label) for label in labels):
            raise ValueError("notification_redact_values entries must be IP addresses or DNS names")
        unique.setdefault(lowered, None)
    return list(unique)


#: Labels one indicator may carry at most.
MAX_OPENCTI_LABELS: Final[int] = 20


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


def normalise_smb_actions(value: list[str]) -> list[str]:
    """Normalise `OCC_SMB_IGNORE_ACTIONS` into lower-case, unique action names.

    The comparison happens against `AUDITACTION` from the wire, which Samba
    writes in lower case; normalising here means `OpenAt` and `openat` are one
    entry, not two, and a trailing comma is harmless. Control characters are
    rejected rather than stripped: a value that could never match is a
    configuration mistake worth seeing at startup.
    """
    unique: dict[str, None] = {}
    for raw in value:
        action = raw.strip().lower()
        if not action:
            continue
        if len(action) > MAX_SMB_ACTION_LENGTH:
            raise ValueError(f"smb_ignore_actions entry exceeds {MAX_SMB_ACTION_LENGTH} characters")
        if any(ord(character) < 32 or ord(character) == 127 for character in action):
            raise ValueError("smb_ignore_actions must not contain control characters")
        unique.setdefault(action, None)
    return list(unique)


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


def normalise_opencti_url(value: Any) -> Any:
    """Treat an unset or blank ``OCC_OPENCTI_URL`` as "not configured"."""
    if value is None:
        return None
    if isinstance(value, str):
        text = value.strip()
        return text or None
    return value


def require_opencti_url(value: str | None) -> str | None:
    """Accept an https base URL, and plain http only for a loopback appliance.

    The client appends ``/graphql`` to this value, so a query string or fragment
    would silently produce a different endpoint than the operator typed. Error
    messages name the setting and, at most, the host: a tenant path ends up in
    the container log otherwise.
    """
    if value is None:
        return None
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError(
            f"opencti_url must be an http(s) URL, got scheme {parsed.scheme or '<none>'!r}"
        )
    if not parsed.hostname:
        raise ValueError("opencti_url must name a host")
    if parsed.scheme == "http" and parsed.hostname not in LOOPBACK_HOSTS:
        raise ValueError(
            f"opencti_url must use https unless it is loopback (host {parsed.hostname!r})"
        )
    if parsed.query or parsed.fragment:
        raise ValueError("opencti_url must not carry a query string or fragment")
    return value


def normalise_opencti_token(value: Any) -> Any:
    """An empty ``OCC_OPENCTI_TOKEN`` means "no token", not an empty secret."""
    if isinstance(value, SecretStr):
        return value if value.get_secret_value().strip() else None
    if isinstance(value, str):
        text = value.strip()
        return text or None
    return value


def normalise_opencti_create_mode(value: Any) -> Any:
    """`off`, `missing` and `always` are case-insensitive setting values."""
    if not isinstance(value, str):
        return value
    return value.strip().lower()


def normalise_misp_url(value: Any) -> Any:
    """Treat an unset or blank ``OCC_MISP_URL`` as "not configured"."""
    if value is None:
        return None
    if isinstance(value, str):
        text = value.strip()
        return text or None
    return value


def require_misp_url(value: str | None) -> str | None:
    """Accept an http(s) MISP base URL; plain http only for a loopback lab.

    MISP may live under a path (for example ``/misp``), so the path is kept.
    A query string or fragment would be silently discarded by the API client and
    could hide a credential or tenant selector in the configuration, so both are
    refused.
    """
    if value is None:
        return None
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError(
            f"misp_url must be an http(s) URL, got scheme {parsed.scheme or '<none>'!r}"
        )
    if not parsed.hostname:
        raise ValueError("misp_url must name a host")
    if parsed.scheme == "http" and parsed.hostname not in LOOPBACK_HOSTS:
        raise ValueError(
            f"misp_url must use https unless it is loopback (host {parsed.hostname!r})"
        )
    if parsed.query or parsed.fragment:
        raise ValueError("misp_url must not carry a query string or fragment")
    return value.rstrip("/")


def normalise_misp_api_key(value: Any) -> Any:
    """An empty ``OCC_MISP_API_KEY`` means "no key", not an empty secret."""
    if isinstance(value, SecretStr):
        return value if value.get_secret_value().strip() else None
    if isinstance(value, str):
        text = value.strip()
        return text or None
    return value


def normalise_misp_publish_mode(value: Any) -> Any:
    """`draft` and `auto` are case-insensitive setting values."""
    if not isinstance(value, str):
        return value
    return value.strip().lower()


def validate_misp_handling(value: str, *, name: str, allowed: tuple[str, ...]) -> str:
    """Validate a TLP/PAP level and return the lower-case machine value."""
    text = value.strip().lower()
    if text not in allowed:
        raise ValueError(f"{name} must be one of: " + ", ".join(allowed))
    return text


def validate_misp_tags(value: list[str]) -> list[str]:
    """Normalise free-form MISP tags without allowing invisible control text."""
    unique: dict[str, None] = {}
    for raw in value:
        tag = raw.strip()
        if not tag:
            continue
        if len(tag) > MAX_MISP_TAG_LENGTH:
            raise ValueError(f"misp_tags entry exceeds {MAX_MISP_TAG_LENGTH} characters")
        if any(ord(character) < 32 or ord(character) == 127 for character in tag):
            raise ValueError("misp_tags must not contain control characters")
        unique.setdefault(tag, None)
    return list(unique)


def validate_misp_namespace(value: str) -> str:
    """A namespace is part of deterministic UUIDs; keep it portable and short."""
    text = value.strip()
    if not 1 <= len(text) <= MAX_MISP_NAMESPACE_LENGTH:
        raise ValueError(f"misp_event_namespace must be 1..{MAX_MISP_NAMESPACE_LENGTH} characters")
    if not re.fullmatch(r"[A-Za-z0-9._:-]+", text):
        raise ValueError(
            "misp_event_namespace may contain only letters, digits, "
            "dot, underscore, colon and hyphen"
        )
    return text


def validate_misp_to_ids_types(value: list[str]) -> list[str]:
    """Only known incident names may opt into the IDS flag."""
    normalised = [name.strip() for name in value if name.strip()]
    unknown = sorted(set(normalised) - set(INCIDENT_KEY_PREFIX))
    if unknown:
        raise ValueError("unknown misp_to_ids_types entries: " + ", ".join(unknown))
    return list(dict.fromkeys(normalised))


def require_misp_config(
    *,
    enabled: bool,
    url: str | None,
    api_key: SecretStr | None,
    distribution: int,
    sharing_group_id: int | None,
) -> None:
    """Refuse a half-configured MISP publisher at startup.

    Distribution ``4`` means a sharing group; without its id MISP cannot resolve
    the audience. The opposite combination is also a mistake: a sharing-group id
    on an event that does not use sharing groups is ignored silently.
    """
    if distribution == 4 and sharing_group_id is None:
        raise ValueError("OCC_MISP_SHARING_GROUP_ID is required when OCC_MISP_DISTRIBUTION=4")
    if distribution != 4 and sharing_group_id is not None:
        raise ValueError("OCC_MISP_SHARING_GROUP_ID requires OCC_MISP_DISTRIBUTION=4")
    if not enabled:
        return
    if url is None:
        raise ValueError("OCC_MISP_URL is required when OCC_MISP_ENABLED=true")
    if api_key is None:
        raise ValueError("OCC_MISP_API_KEY is required when OCC_MISP_ENABLED=true")


def validate_opencti_labels(value: list[str]) -> list[str]:
    """Normalise indicator labels and reject values STIX would not carry.

    Blank entries are dropped and duplicates collapse, so a stray comma is
    harmless. Control characters and oversized entries are refused: a label is
    copied into every indicator the correlator creates, and a typo there is only
    visible after it has been written to a third party.
    """
    unique: dict[str, None] = {}
    for raw in value:
        label = raw.strip()
        if not label:
            continue
        if len(label) > MAX_OPENCTI_LABEL_LENGTH:
            raise ValueError(f"opencti_labels entry exceeds {MAX_OPENCTI_LABEL_LENGTH} characters")
        if any(ord(character) < 32 or ord(character) == 127 for character in label):
            raise ValueError("opencti_labels must not contain control characters")
        unique.setdefault(label, None)
    if len(unique) > MAX_OPENCTI_LABELS:
        raise ValueError(f"opencti_labels accepts at most {MAX_OPENCTI_LABELS} entries")
    return list(unique)


def require_opencti_config(
    *,
    lookup_enabled: bool,
    create_mode: str,
    url: str | None,
    token: SecretStr | None,
) -> None:
    """Refuse a half-configured OpenCTI integration at startup.

    Enabling the lookup, or a create mode other than ``off``, promises a
    provider the correlator will call. Without both a URL and a token nothing
    would ever reach it and the operator would read "off" instead of
    "misconfigured". Creation is a write to a third party, so it needs the same
    credentials the lookup does.
    """
    if not lookup_enabled and create_mode == "off":
        return
    if url is None:
        raise ValueError("OCC_OPENCTI_URL is required when OpenCTI lookup or create is enabled")
    if token is None:
        raise ValueError("OCC_OPENCTI_TOKEN is required when OpenCTI lookup or create is enabled")


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
    "DEFAULT_MISP_TO_IDS_TYPES",
    "DIGEST_TIME_RE",
    "KNOWN_CHANNEL_NAMES",
    "LOOPBACK_HOSTS",
    "MAX_INCIDENT_HORIZON_SECONDS",
    "MAX_MISP_NAMESPACE_LENGTH",
    "MAX_MISP_TAG_LENGTH",
    "MAX_NOTIFICATION_REDACT_VALUES",
    "MAX_NOTIFICATION_REDACT_VALUE_LENGTH",
    "MAX_OPENCTI_LABELS",
    "MAX_OPENCTI_LABEL_LENGTH",
    "MISP_PAP_LEVELS",
    "MISP_PUBLISH_MODES",
    "MISP_TLP_LEVELS",
    "OPENCTI_CREATE_MODES",
    "SERVICE_CATEGORIES",
    "TELEGRAM_TOKEN_RE",
    "decode_incident_horizons",
    "disable_health_port",
    "health_allowlist_or_loopback",
    "normalise_alert_detail",
    "normalise_health_host",
    "normalise_log_file",
    "normalise_log_level",
    "normalise_misp_api_key",
    "normalise_misp_publish_mode",
    "normalise_misp_url",
    "normalise_notification_redact_values",
    "normalise_opencti_create_mode",
    "normalise_opencti_token",
    "normalise_opencti_url",
    "normalise_service_severity",
    "require_email_address",
    "require_http_urls",
    "require_misp_config",
    "require_misp_url",
    "require_opencti_config",
    "require_opencti_url",
    "require_redis_scheme",
    "require_slack_endpoints",
    "slack_configured_but_disabled",
    "split_comma_separated",
    "validate_allowed_ips",
    "validate_digest_time",
    "validate_incident_horizons",
    "validate_misp_handling",
    "validate_misp_namespace",
    "validate_misp_tags",
    "validate_misp_to_ids_types",
    "validate_opencti_labels",
    "validate_service_categories",
    "validate_service_channels",
    "validate_telegram_token",
]
