"""Channel-aware alert rendering for chat and e-mail messages.

Three detail levels are supported, selected per channel in the configuration:

* ``minimal``  — the legacy single line, byte-identical to the old correlator.
* ``standard`` — instance block (node name, host IP), then the attacker block
  (source IP and port), the detection time and a one-entry log message summary.
* ``detailed`` — ``standard`` plus destination address, event counter and up to
  three log entries.

Every line is separated with CRLF so Telegram, Discord, Slack and SMTP clients
render them as distinct lines. Rendering is defensive on purpose: fields come
from network input, so control characters are stripped (log injection), long
values are clipped, and anything inside ``logdata`` whose key looks like a
credential is masked before it can reach a chat channel.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Final, Literal, Protocol

AlertDetail = Literal["minimal", "standard", "detailed"]
AlertFlavor = Literal["telegram", "slack", "discord", "plain"]

#: Accepted values for the per-channel ``*_detail`` settings, in increasing order.
ALERT_DETAIL_LEVELS: Final[tuple[AlertDetail, ...]] = ("minimal", "standard", "detailed")

#: Line separator used inside a rendered alert.
CRLF: Final[str] = "\r\n"

_MAX_FIELD: Final[int] = 160
_MAX_LOG_ENTRIES: Final[int] = 3
_MAX_LOG_ITEMS: Final[int] = 10
_MAX_LOG_PAIRS: Final[int] = 6
_MAX_LOG_VALUE: Final[int] = 120
_MAX_LOG_KEY: Final[int] = 40
_REDACTED: Final[str] = "***"
#: Sentinel for "this address has no port", matching the event schema default.
_NO_PORT: Final[int] = -1

#: Keys whose value must never leave the correlator.
_SECRET_MARKERS: Final[tuple[str, ...]] = (
    "PASSWORD",
    "PASSWD",
    "PASS",
    "SECRET",
    "TOKEN",
    "APIKEY",
    "API_KEY",
    "AUTH",
    "PRIVATE",
)

_CONTROL_CHARS: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]+")
#: MarkdownV2 reserved characters; an unescaped one makes Telegram reject the message.
_TELEGRAM_RESERVED: Final[re.Pattern[str]] = re.compile(r"([_*\[\]()~`>#+\-=|{}.!\\])")


class AlertIncident(Protocol):
    """Incident fields the renderer needs (see :class:`Incident`)."""

    key: str
    node_id: str
    src_host: str
    src_port: int
    dst_host: str
    dst_port: int
    created: int
    events_count: int
    logdata: str | None
    description: str

    @property
    def display_description(self) -> str:
        """Incident name to show in the alert header."""
        ...

    def format_report_short(self) -> str:
        """Return the legacy one-line report, used by the ``minimal`` level."""
        ...


def _clean(value: object, limit: int = _MAX_FIELD) -> str:
    """Strip control characters, collapse whitespace and clip a field."""
    text = _CONTROL_CHARS.sub(" ", str(value))
    text = " ".join(text.split())
    if len(text) > limit:
        return text[: limit - 1] + "…"
    return text


def _escape(text: str, flavor: AlertFlavor) -> str:
    """Escape text for the markup dialect of `flavor`."""
    if flavor == "telegram":
        return _TELEGRAM_RESERVED.sub(r"\\\1", text)
    if flavor == "slack":
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return text


def _bold(label: str, flavor: AlertFlavor) -> str:
    """Render `label:` bold for `flavor`, or plain."""
    if flavor == "plain":
        return f"{label}:"
    markers = "**" if flavor == "discord" else "*"
    return f"{markers}{_escape(label, flavor)}:{markers}"


def _line(emoji: str, label: str, value: object, flavor: AlertFlavor) -> str:
    """One `emoji label value` row, escaped for the channel."""
    rendered = _escape(_clean(value), flavor)
    return f"{emoji} {_bold(label, flavor)} {rendered}"


def _header(description: str, flavor: AlertFlavor) -> str:
    """Bold incident description used as the first line."""
    title = _clean(description)
    if flavor == "plain":
        return f"OpenCanary: {title}"
    markers = "**" if flavor == "discord" else "*"
    return f"🛡 OpenCanary: {markers}{_escape(title, flavor)}{markers}"


def _decode_logdata(logdata: str | None) -> list[object]:
    """Decode the stored `logdata` JSON, tolerating legacy shapes."""
    if not logdata:
        return []
    try:
        parsed = json.loads(logdata)
    except (json.JSONDecodeError, TypeError):
        return []
    if isinstance(parsed, list):
        return parsed
    return [parsed]


def _is_secret_key(key: str) -> bool:
    upper = key.upper()
    return any(marker in upper for marker in _SECRET_MARKERS)


def _log_value(key: str, value: object) -> str:
    """Render one log field, masking anything that looks like a credential."""
    if _is_secret_key(key):
        return _REDACTED
    if isinstance(value, str):
        return _clean(value, _MAX_LOG_VALUE)
    if isinstance(value, (int, float, bool)) or value is None:
        return _clean(value, _MAX_LOG_VALUE)
    return _clean(json.dumps(value, ensure_ascii=False, default=str), _MAX_LOG_VALUE)


def log_summary(
    logdata: str | None,
    *,
    max_entries: int = _MAX_LOG_ENTRIES,
    max_items: int = _MAX_LOG_ITEMS,
) -> str:
    """Summarise stored log data without leaking credentials.

    Dictionaries render as ``KEY=value`` pairs with secret keys masked; a flat
    list (host and network port scans store their evidence that way) renders as
    a comma-separated list of the first entries. The two limits let the detail
    level decide how much evidence the channel shows.
    """
    entries = _decode_logdata(logdata)
    if not entries:
        return ""
    if all(not isinstance(entry, (dict, list)) for entry in entries):
        shown = [_clean(entry, _MAX_LOG_VALUE) for entry in entries[:max_items]]
        text = ", ".join(item for item in shown if item)
        hidden = len(entries) - len(shown)
        return f"{text} (+{hidden} more)" if hidden > 0 else text

    rendered: list[str] = []
    for entry in entries[:max_entries]:
        if isinstance(entry, dict):
            pairs = [
                f"{_clean(key, _MAX_LOG_KEY)}={_log_value(str(key), value)}"
                for key, value in list(entry.items())[:_MAX_LOG_PAIRS]
            ]
            if pairs:
                rendered.append(", ".join(pairs))
        else:
            rendered.append(_clean(entry, _MAX_LOG_VALUE))
    return " | ".join(item for item in rendered if item)


def _format_time(created: int) -> str:
    """Render an incident epoch as a UTC timestamp."""
    try:
        moment = datetime.fromtimestamp(created, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return "unknown"
    return moment.strftime("%Y-%m-%d %H:%M:%S UTC")


def _address(host: str, port: int) -> str:
    """Render `host:port`, falling back to the host when no port was recorded.

    The event schema uses ``-1`` for "not reported", so a negative port must not
    turn into ``host:-1``. An empty host becomes ``unknown`` rather than an
    empty value next to its label.
    """
    address = _clean(host) or "unknown"
    if port is None or port < 0:
        return address
    return f"{address}:{int(port)}"


def clip(text: str, limit: int | None) -> str:
    """Cut `text` to `limit` characters without leaving a dangling escape.

    Telegram rejects MarkdownV2 when a message ends in a lone backslash, which a
    naive slice can produce, so trailing backslashes are dropped.
    """
    if limit is None or len(text) <= limit:
        return text
    cut = text[: max(0, limit - 1)]
    while cut.endswith("\\"):
        cut = cut[:-1]
    return cut + "…"


def render_alert(
    incident: AlertIncident,
    *,
    detail: AlertDetail = "standard",
    flavor: AlertFlavor = "plain",
    max_length: int | None = None,
) -> str:
    """Render one incident message for a channel.

    ``minimal`` returns the legacy one-line report untouched, so a deployment
    that never sets a detail level keeps exactly the old message. ``standard``
    and ``detailed`` return the multiline layout separated by CRLF.
    """
    if detail == "minimal":
        return clip(incident.format_report_short(), max_length)

    lines: list[str] = [
        _header(incident.display_description, flavor),
        "",
        _line("🖥", "Instance", incident.node_id, flavor),
        _line("🌐", "IP", _address(incident.dst_host, _NO_PORT), flavor),
        "",
        _line("🎯", "Attacker", _address(incident.src_host, incident.src_port), flavor),
        _line("🕒", "Time", _format_time(incident.created), flavor),
    ]

    detailed = detail == "detailed"
    if detailed:
        lines.extend(
            [
                "",
                _line("🔌", "Destination", _address(incident.dst_host, incident.dst_port), flavor),
                _line("📊", "Events", incident.events_count, flavor),
            ]
        )
    summary = log_summary(
        incident.logdata,
        max_entries=_MAX_LOG_ENTRIES if detailed else 1,
        max_items=_MAX_LOG_ITEMS if detailed else 5,
    )
    if summary:
        if not detailed:
            lines.append("")
        lines.append(_line("📝", "Log", summary, flavor))

    return clip(CRLF.join(lines), max_length)


__all__ = [
    "ALERT_DETAIL_LEVELS",
    "CRLF",
    "AlertDetail",
    "AlertFlavor",
    "AlertIncident",
    "clip",
    "log_summary",
    "render_alert",
]
