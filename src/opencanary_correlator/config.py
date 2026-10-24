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
from typing import Annotated, Any, Final, Literal
from urllib.parse import urlparse

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from opencanary_correlator.constants import INCIDENT_KEY_PREFIX

_logger = logging.getLogger(__name__)

LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]

CommaSeparated = Annotated[list[str], NoDecode]

#: Legacy `.conf` key -> :class:`Settings` field.
LEGACY_KEY_MAP: Final[dict[str, str]] = {
    "console.incident_horizon": "incident_horizon",
    "portscan.packet_threshold": "scan_host_threshold",
    "portscan.monitor_period": "scan_host_horizon",
    "networkscan.packet_threshold": "scan_network_threshold",
    "networkscan.monitor_period": "scan_network_horizon",
    "console.email_notification_address": "smtp_to",
    "console.email_host": "smtp_host",
    "console.email_port": "smtp_port",
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

#: Upper bound for a per-incident horizon, in seconds (one week).
MAX_INCIDENT_HORIZON_SECONDS: Final[float] = 7 * 24 * 3600.0

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
    tcp_enabled: bool = True
    tcp_host: str = "0.0.0.0"  # noqa: S104 - network service default, override with OCC_TCP_HOST
    tcp_port: int = Field(default=1514, ge=1, le=65535)

    syslog_enabled: bool = False
    syslog_host: str = "0.0.0.0"  # noqa: S104 - network service default, override with OCC_SYSLOG_HOST
    syslog_port: int = Field(default=5514, ge=1, le=65535)
    syslog_udp_enabled: bool = False

    # --- Hardening ----------------------------------------------------------
    max_line_bytes: int = Field(default=65536, ge=1024, le=10 * 1024 * 1024)
    partial_line_timeout: float = Field(default=30.0, gt=0.0, le=3600.0)
    max_connections: int = Field(default=1000, ge=1, le=100_000)
    event_queue_size: int = Field(default=10_000, ge=1, le=1_000_000)
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

    # --- Dispatchers --------------------------------------------------------
    webhook_urls: CommaSeparated = Field(default_factory=list)
    slack_webhooks: CommaSeparated = Field(default_factory=list)
    discord_webhooks: CommaSeparated = Field(default_factory=list)
    telegram_token: SecretStr | None = None
    telegram_chat_ids: CommaSeparated = Field(default_factory=list)

    smtp_host: str | None = None
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_username: str | None = None
    smtp_password: SecretStr | None = None
    smtp_from: str = "notifications@opencanary.invalid"
    smtp_to: CommaSeparated = Field(default_factory=list)
    smtp_starttls: bool = True
    dispatch_timeout: float = Field(default=10.0, gt=0.0, le=300.0)

    # --- Observability ------------------------------------------------------
    log_level: LogLevel = "INFO"
    health_port: int | None = Field(default=8080, ge=1, le=65535)

    @field_validator(
        "webhook_urls",
        "slack_webhooks",
        "discord_webhooks",
        "telegram_chat_ids",
        "smtp_to",
        mode="before",
    )
    @classmethod
    def _split_comma_separated(cls, value: Any) -> Any:
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

    @field_validator("webhook_urls", "slack_webhooks", "discord_webhooks")
    @classmethod
    def _require_http_urls(cls, value: list[str]) -> list[str]:
        for url in value:
            scheme = urlparse(url).scheme
            if scheme not in {"http", "https"}:
                raise ValueError(f"webhook URL must be http(s): {url!r}")
        return value

    @field_validator("incident_horizons", mode="before")
    @classmethod
    def _decode_incident_horizons(cls, value: Any) -> Any:
        if value is None or value == "":
            return {}
        if isinstance(value, str):
            try:
                return json.loads(value)
            except json.JSONDecodeError as exc:
                raise ValueError("incident_horizons must be a JSON object") from exc
        return value

    @field_validator("incident_horizons")
    @classmethod
    def _validate_incident_horizons(cls, value: dict[str, float]) -> dict[str, float]:
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

    @field_validator("redis_url")
    @classmethod
    def _require_redis_scheme(cls, value: str) -> str:
        if not value.startswith(("redis://", "rediss://", "unix://")):
            raise ValueError("redis_url must start with redis://, rediss:// or unix://")
        return value

    @field_validator("log_level", mode="before")
    @classmethod
    def _normalise_log_level(cls, value: Any) -> Any:
        return value.upper() if isinstance(value, str) else value

    @field_validator("smtp_from")
    @classmethod
    def _require_email_address(cls, value: str) -> str:
        if "@" not in value or value.startswith("@") or value.endswith("@"):
            raise ValueError("smtp_from must be an email address")
        return value

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
        mapped: dict[str, Any] = {}
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
        merged = {**mapped, **explicit}
        return cls(_env_file=None, **merged)


__all__ = [
    "LEGACY_DROPPED_PREFIXES",
    "LEGACY_INCIDENT_HORIZON_KEYS",
    "LEGACY_KEY_MAP",
    "MAX_INCIDENT_HORIZON_SECONDS",
    "LogLevel",
    "Settings",
]
