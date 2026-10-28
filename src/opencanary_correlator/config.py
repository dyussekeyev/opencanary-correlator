"""Typed configuration loaded from environment variables and `.env`.

All settings use the ``OCC_`` prefix, e.g. ``OCC_REDIS_URL``. Secrets are held
in :class:`pydantic.SecretStr` so they never appear in ``repr()`` or JSON dumps.
The legacy JSON configuration file is still importable through
:meth:`Settings.from_legacy_json`.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Annotated, Any, Final, Literal, Self

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from opencanary_correlator.config_validation import (
    DEFAULT_HEALTH_ALLOWED_IPS,
    DEFAULT_HEALTH_HOST,
    DEFAULT_HEALTH_PORT,
    DEFAULT_INTAKE_HOST,
    MAX_INCIDENT_HORIZON_SECONDS,
    decode_incident_horizons,
    disable_health_port,
    health_allowlist_or_loopback,
    normalise_alert_detail,
    normalise_health_host,
    normalise_log_file,
    normalise_log_level,
    require_email_address,
    require_http_urls,
    require_redis_scheme,
    require_slack_endpoints,
    split_comma_separated,
    validate_allowed_ips,
    validate_incident_horizons,
    validate_telegram_token,
)
from opencanary_correlator.connectors.receivers._allowlist import parse_allowed_networks
from opencanary_correlator.constants import INCIDENT_KEY_PREFIX, MAX_EVENT_COUNT

_logger = logging.getLogger(__name__)

LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]

#: How much of an incident a channel puts in the message. ``minimal`` is the
#: legacy single-line alert; see ``connectors.dispatchers.alert_text``.
AlertDetail = Literal["minimal", "standard", "detailed"]

CommaSeparated = Annotated[list[str], NoDecode]

#: Legacy `.conf` key -> :class:`Settings` field.
LEGACY_KEY_MAP: Final[dict[str, str]] = {
    "console.incident_horizon": "incident_horizon",
    "portscan.packet_threshold": "scan_host_threshold",
    "portscan.monitor_period": "scan_host_horizon",
    "networkscan.packet_threshold": "scan_network_threshold",
    "networkscan.monitor_period": "scan_network_horizon",
    "console.email_notification_enable": "smtp_enabled",
    "console.email_notification_address": "smtp_to",
    "console.email_host": "smtp_host",
    "console.email_port": "smtp_port",
    "console.slack_notification_enable": "slack_enabled",
    "console.slack_notification_webhook": "slack_webhooks",
}

#: Legacy per-incident horizon key -> canonical incident name.
LEGACY_INCIDENT_HORIZON_KEYS: Final[dict[str, str]] = {
    "ftp.incident_horizon": "ftp.login_attempt",
    "http.incident_horizon": "http.login_attempt",
    "ssh.incident_horizon": "ssh.login_attempt",
    "telnet.incident_horizon": "telnet.login_attempt",
    # The legacy code spelled the key with a missing "p"; keep it for parity.
    "httproxy.incident_horizon": "httpproxy.login_attempt",
    "mysql.incident_horizon": "mysql.login_attempt",
    "mssql.incident_horizon": "mssql.login_attempt",
    "tftp.incident_horizon": "tftp.action",
    "ntp.incident_horizon": "ntp.monlist",
    "vnc.incident_horizon": "vnc.login_attempt",
    "snmp.incident_horizon": "snmp.cmd",
    "rdp.incident_horizon": "rdp.login_attempt",
    "sip.incident_horizon": "sip.login_attempt",
    "smb.file_open_horizon": "smb.file_open",
    "scans.host_portscan_horizon": "scans.host_portscan",
    "scans.network_portscan_horizon": "scans.network_portscan",
}

#: Legacy keys that are intentionally not migrated to the new settings.
LEGACY_DROPPED_PREFIXES: Final[tuple[str, ...]] = (
    "twilio.",
    "console.mandrill_key",
    "console.sms_notification",
)


class Settings(BaseSettings):
    """Runtime configuration of the correlator."""

    model_config = SettingsConfigDict(
        env_prefix="OCC_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        validate_default=True,
    )

    # --- Event intake -------------------------------------------------------
    # Loopback by default: the common deployment runs the canary and the
    # correlator on the same host, and an intake port open on every interface is
    # an unauthenticated write path into the incident store. A remote canary
    # needs OCC_TCP_HOST=0.0.0.0 (or the address it should listen on).
    tcp_enabled: bool = True
    tcp_host: str = Field(default=DEFAULT_INTAKE_HOST, max_length=253)
    # Ports are deliberately outside the well-known and emulated-service ranges:
    # a honeypot imitates 21, 80, 443, 8080 and friends, so binding a correlator
    # listener next to them invites collisions with the traps themselves.
    tcp_port: int = Field(default=15140, ge=1, le=65535)

    syslog_enabled: bool = False
    syslog_host: str = Field(default=DEFAULT_INTAKE_HOST, max_length=253)
    syslog_port: int = Field(default=15141, ge=1, le=65535)
    syslog_udp_enabled: bool = False

    # --- Hardening ----------------------------------------------------------
    max_line_bytes: int = Field(default=65536, ge=1024, le=10 * 1024 * 1024)
    partial_line_timeout: float = Field(default=30.0, gt=0.0, le=3600.0)
    max_connections: int = Field(default=1000, ge=1, le=100_000)
    receiver_allowed_ips: CommaSeparated = Field(
        default_factory=list,
        description=(
            "Comma-separated CIDRs or addresses allowed to send events to the receivers. "
            "Empty allows every peer."
        ),
    )
    event_queue_size: int = Field(default=10_000, ge=1, le=1_000_000)
    event_concurrency: int = Field(
        default=8,
        ge=1,
        le=64,
        description=(
            "Consumer lanes per receiver. Events are sharded by source host, so one "
            "slow host cannot stall the others and per-host order is preserved."
        ),
    )
    rate_limit_events_per_minute: int = Field(default=600, ge=0, le=1_000_000)

    # --- State --------------------------------------------------------------
    redis_url: str = Field(description="redis://, rediss:// or unix:// connection URL")

    # --- Correlation --------------------------------------------------------
    incident_horizon: float = Field(default=60.0, ge=0.0)
    incident_horizons: dict[str, float] = Field(
        default_factory=dict,
        description=(
            "Per-incident overrides of incident_horizon, keyed by canonical incident name "
            "(e.g. ftp.login_attempt)"
        ),
    )
    scan_host_threshold: int = Field(default=5, ge=1)
    scan_host_horizon: float = Field(default=50.0, gt=0.0)
    scan_network_threshold: int = Field(default=2, ge=1)
    scan_network_horizon: float = Field(default=3600.0, gt=0.0)
    dedup_ttl: float = Field(default=60.0, ge=0.0)
    incident_lookup_scan_limit: int = Field(
        default=100,
        ge=1,
        le=10_000,
        description=(
            "Newest incidents inspected when a host has no incident-latest pointer. "
            "The fallback lookup is capped, so ingestion cost does not grow with the "
            "size of the incidents index."
        ),
    )
    max_stored_events: int = Field(
        default=MAX_EVENT_COUNT,
        ge=1,
        le=10_000,
        description=(
            "Timestamps and log entries kept per incident. The legacy console renders "
            "at most 100 entries, so a larger value only helps direct Redis readers; "
            "events_count always stays exact."
        ),
    )

    # --- Dispatchers --------------------------------------------------------
    # Webhook URLs carry their credential in the path or query string, so they
    # are kept out of `repr()`: the docstring above promises that secrets never
    # show up there, and a `repr()` in a traceback or debug print is exactly how
    # such a promise gets broken. `--check-config` never prints them either.
    webhook_urls: CommaSeparated = Field(default_factory=list, repr=False)
    # A channel switch that starts off: `enabled` is a real decision, not a
    # default that silently does nothing without a webhook (see
    # `require_slack_endpoints`).
    slack_enabled: bool = False
    slack_webhooks: CommaSeparated = Field(default_factory=list, repr=False)
    discord_webhooks: CommaSeparated = Field(default_factory=list, repr=False)
    telegram_token: SecretStr | None = None
    telegram_chat_ids: CommaSeparated = Field(default_factory=list)

    smtp_enabled: bool = True
    smtp_host: str | None = None
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_username: str | None = None
    smtp_password: SecretStr | None = None
    smtp_from: str = "notifications@opencanary.invalid"
    smtp_to: CommaSeparated = Field(default_factory=list)
    smtp_starttls: bool = True
    smtp_use_tls: bool = False
    dispatch_timeout: float = Field(default=10.0, gt=0.0, le=300.0)

    # --- Alert detail per channel -------------------------------------------
    # `minimal` keeps the legacy message byte-for-byte; `standard` sends the
    # multiline instance/attacker layout; `detailed` adds destination, counters
    # and a redacted log summary. Chat channels default to the readable layout,
    # while webhook and SMTP stay on the legacy text so existing SIEM parsers and
    # mail filters keep working until the level is raised explicitly.
    telegram_detail: AlertDetail = "standard"
    slack_detail: AlertDetail = "standard"
    discord_detail: AlertDetail = "standard"
    webhook_detail: AlertDetail = "minimal"
    smtp_detail: AlertDetail = "minimal"

    # --- Observability ------------------------------------------------------
    log_level: LogLevel = "INFO"
    # Operational log file. Empty means "stderr only", which is what containers
    # rely on; a path adds a size-rotated UTF-8 file without changing stderr or
    # the JSON audit stream on stdout. See `log_setup.py`.
    log_file: str | None = Field(default=None, max_length=4096)
    # 0 is a valid input and means "disabled"; the before-validator maps it to
    # None, so the 1..65535 bound only applies to enabled ports. The default
    # avoids 8080, which honeypot modules imitate as an alternative HTTP port.
    health_port: int | None = Field(default=DEFAULT_HEALTH_PORT, ge=0, le=65535)
    # Every interface by default, because probes often arrive from a different
    # pod or the Docker bridge. Set 127.0.0.1 (or ::1) to keep the unauthenticated
    # listener on loopback and reach it through a sidecar or `docker exec`.
    health_host: str = Field(default=DEFAULT_HEALTH_HOST, max_length=253)
    health_allowed_ips: CommaSeparated = Field(
        default_factory=lambda: list(DEFAULT_HEALTH_ALLOWED_IPS),
        description=(
            "Comma-separated CIDRs or addresses allowed to read /healthz, /readyz and "
            "/metrics. Defaults to loopback; an empty value also falls back to loopback."
        ),
    )

    @field_validator(
        "webhook_urls",
        "slack_webhooks",
        "discord_webhooks",
        "telegram_chat_ids",
        "smtp_to",
        "receiver_allowed_ips",
        "health_allowed_ips",
        mode="before",
    )
    @classmethod
    def _split_comma_separated(cls, value: Any) -> Any:
        return split_comma_separated(value)

    @field_validator("webhook_urls", "slack_webhooks", "discord_webhooks")
    @classmethod
    def _require_http_urls(cls, value: list[str]) -> list[str]:
        return require_http_urls(value)

    @field_validator("telegram_token")
    @classmethod
    def _validate_telegram_token(cls, value: SecretStr | None) -> SecretStr | None:
        return validate_telegram_token(value)

    @field_validator("receiver_allowed_ips", "health_allowed_ips")
    @classmethod
    def _validate_allowed_ips(cls, value: list[str]) -> list[str]:
        return validate_allowed_ips(value)

    @field_validator("health_allowed_ips")
    @classmethod
    def _health_allowlist_never_open(cls, value: list[str]) -> list[str]:
        return health_allowlist_or_loopback(value)

    @field_validator("incident_horizons", mode="before")
    @classmethod
    def _decode_incident_horizons(cls, value: Any) -> Any:
        return decode_incident_horizons(value)

    @field_validator("incident_horizons")
    @classmethod
    def _validate_incident_horizons(cls, value: dict[str, float]) -> dict[str, float]:
        return validate_incident_horizons(value)

    @field_validator("redis_url")
    @classmethod
    def _require_redis_scheme(cls, value: str) -> str:
        return require_redis_scheme(value)

    @field_validator("log_level", mode="before")
    @classmethod
    def _normalise_log_level(cls, value: Any) -> Any:
        return normalise_log_level(value)

    @field_validator("log_file", mode="before")
    @classmethod
    def _normalise_log_file(cls, value: Any) -> Any:
        return normalise_log_file(value)

    @field_validator(
        "telegram_detail",
        "slack_detail",
        "discord_detail",
        "webhook_detail",
        "smtp_detail",
        mode="before",
    )
    @classmethod
    def _normalise_alert_detail(cls, value: Any) -> Any:
        return normalise_alert_detail(value)

    @field_validator("smtp_from")
    @classmethod
    def _require_email_address(cls, value: str) -> str:
        return require_email_address(value)

    @model_validator(mode="after")
    def _validate_smtp_tls(self) -> Self:
        """Reject ambiguous SMTP encryption settings.

        ``start_tls`` performs an explicit STARTTLS upgrade (usually port 587);
        ``use_tls`` wraps the connection immediately (usually port 465).
        ``aiosmtplib`` rejects both at once, so fail at configuration time.
        """
        if self.smtp_use_tls and self.smtp_starttls:
            raise ValueError("smtp_use_tls and smtp_starttls are mutually exclusive")
        return self

    @model_validator(mode="after")
    def _validate_slack(self) -> Self:
        """An enabled Slack channel must have somewhere to send."""
        require_slack_endpoints(self.slack_enabled, self.slack_webhooks)
        return self

    @field_validator("health_host", mode="before")
    @classmethod
    def _normalise_health_host(cls, value: Any) -> Any:
        return normalise_health_host(value)

    @field_validator("health_port", mode="before")
    @classmethod
    def _disable_health_port(cls, value: Any) -> Any:
        return disable_health_port(value)

    def horizon_for(self, incident_name: str) -> float:
        """Return the effective horizon in seconds for one incident type."""
        return float(self.incident_horizons.get(incident_name, self.incident_horizon))

    @classmethod
    def from_legacy_json(
        cls,
        path: str | Path,
        *,
        overrides: dict[str, Any] | None = None,
    ) -> Settings:
        """Build settings from the Python 2-era ``opencanary_correlator.conf``.

        Unknown and dropped keys are logged at INFO level; credentials for
        removed integrations (Twilio, Mandrill) are never migrated.
        """
        raw: dict[str, Any] = json.loads(Path(path).read_text(encoding="utf-8"))
        # The Python 2 notifier treated a missing enable key as disabled, even
        # when addresses/webhooks were present. Preserve that default when the
        # legacy file is imported; explicit overrides still win below.
        mapped: dict[str, Any] = {"smtp_enabled": False, "slack_enabled": False}
        dropped: list[str] = []
        horizon_overrides = {
            incident_name: raw[key]
            for key, incident_name in LEGACY_INCIDENT_HORIZON_KEYS.items()
            if key in raw
        }
        for key, value in raw.items():
            if key.startswith(LEGACY_DROPPED_PREFIXES):
                dropped.append(key)
                continue
            if key in LEGACY_INCIDENT_HORIZON_KEYS:
                continue
            field_name = LEGACY_KEY_MAP.get(key)
            if field_name is None:
                dropped.append(key)
                continue
            mapped[field_name] = value
        if dropped:
            _logger.info("legacy settings not migrated: %s", ", ".join(sorted(dropped)))
        explicit = dict(overrides or {})
        if horizon_overrides:
            explicit["incident_horizons"] = {
                **horizon_overrides,
                **dict(explicit.get("incident_horizons") or {}),
            }
        return cls(_env_file=None, **{**mapped, **explicit})


__all__ = [
    "DEFAULT_HEALTH_HOST",
    "DEFAULT_HEALTH_PORT",
    "DEFAULT_INTAKE_HOST",
    "INCIDENT_KEY_PREFIX",
    "LEGACY_DROPPED_PREFIXES",
    "LEGACY_INCIDENT_HORIZON_KEYS",
    "LEGACY_KEY_MAP",
    "MAX_INCIDENT_HORIZON_SECONDS",
    "LogLevel",
    "Settings",
    "parse_allowed_networks",
]
