"""Remove the operator's own honeypot identities from outbound notifications.

A canary captures whatever an attacker sends, and some of it describes the
honeypot itself: an HTTP ``Host`` header, a reverse-proxy ``HOSTNAME`` field, or
the target addresses a network scan collected. Those values are useful evidence
internally, but an alert that leaves the estate through chat, mail or a SIEM must
not map the deployment it reports on.

The filter here is deliberately applied at the last outbound boundary, not in
the incident model: stored events, correlation state and the legacy console keep
the original data, while every rendered string and structured payload is
scrubbed on its way out. Matching is token-aware so ``10.0.0.5`` does not match
inside ``110.0.0.5`` and ``example.test`` does not match ``notexample.test``.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any, Final

#: Replacement for a protected identity. Plain letters on purpose: the filter
#: runs on the finished payload, after Telegram's MarkdownV2 escaping, so a
#: marker containing `*`, `[` or `_` would itself be rejected as unescaped.
REDACTION_MARKER: Final[str] = "REDACTED"

#: Guards against pathological nesting in a payload assembled from network input.
MAX_REDACTION_DEPTH: Final[int] = 16

_BS: Final[str] = "\\"
#: One optional literal backslash. Telegram's MarkdownV2 renders a dot as
#: ``\.`` and a hyphen as ``\-``, so the same pattern must accept both the raw
#: and the escaped spelling; the filter runs after each channel's rendering.
_OPTIONAL_BS: Final[str] = _BS + _BS + "?"
_ESCAPED_DOT: Final[str] = _OPTIONAL_BS + _BS + "."
_ESCAPED_HYPHEN: Final[str] = _OPTIONAL_BS + _BS + "-"


def _escaped_pattern(value: str) -> str:
    """Escape a literal while tolerating chat markdown's backslash escapes."""
    escaped = re.escape(value)
    return escaped.replace(_BS + ".", _ESCAPED_DOT).replace(_BS + "-", _ESCAPED_HYPHEN)


def _ip_pattern(value: str) -> re.Pattern[str]:
    """Return a boundary-aware pattern for one IP literal."""
    escaped = _escaped_pattern(value)
    if ":" in value:
        # IPv6: a boundary is any non-hex, non-colon, non-dot character. The
        # canonical form is matched literally, ignoring hex case; an operator who
        # needs an alternative spelling (expanded or mixed notation) lists that
        # spelling too.
        return re.compile(rf"(?<![0-9A-Fa-f:.]){escaped}(?![0-9A-Fa-f:.])", re.IGNORECASE)
    return re.compile(rf"(?<![\w.-]){escaped}(?![\w.-])")


def _host_pattern(value: str) -> re.Pattern[str]:
    """Return a case-insensitive pattern for a DNS name and its subdomains."""
    label = rf"(?:[A-Za-z0-9]|{_ESCAPED_HYPHEN}){{1,63}}"
    return re.compile(
        rf"(?<![A-Za-z0-9-])(?:{label}{_ESCAPED_DOT})*{_escaped_pattern(value)}(?![A-Za-z0-9-])",
        re.IGNORECASE,
    )


class NotificationIdentityRedactor:
    """Scrub configured honeypot IPs and DNS names from outbound values.

    ``values`` are already normalised by :func:`normalise_notification_redact_values`;
    constructing with an empty list is a no-op and leaves every payload
    byte-identical, which is what keeps an unconfigured deployment unchanged.
    """

    def __init__(self, values: Iterable[str] = ()) -> None:
        ordered = sorted(set(values), key=len, reverse=True)
        self._patterns: tuple[re.Pattern[str], ...] = tuple(
            _ip_pattern(value) if _is_ip(value) else _host_pattern(value) for value in ordered
        )

    @property
    def enabled(self) -> bool:
        """True when at least one identity is protected."""
        return bool(self._patterns)

    def text(self, value: str) -> str:
        """Return ``value`` with every protected identity replaced."""
        if not self._patterns:
            return value
        for pattern in self._patterns:
            value = pattern.sub(REDACTION_MARKER, value)
        return value

    def payload(self, value: Any, *, _depth: int = 0) -> Any:
        """Return a copy of a JSON-like payload with protected identities removed.

        Mappings, lists and tuples are rebuilt rather than mutated: the caller
        may still hold the incident's own structure, and notification scrubbing
        must never rewrite internal state.
        """
        if _depth > MAX_REDACTION_DEPTH:
            return REDACTION_MARKER
        if isinstance(value, Mapping):
            return {
                self.text(str(key)): self.payload(item, _depth=_depth + 1)
                for key, item in value.items()
            }
        if isinstance(value, (list, tuple)):
            return [self.payload(item, _depth=_depth + 1) for item in value]
        if isinstance(value, str):
            return self.text(value)
        return value


def _is_ip(value: str) -> bool:
    """True when a normalised value is an IP literal rather than a DNS name."""
    return ":" in value or value.replace(".", "").isdigit()


__all__ = [
    "MAX_REDACTION_DEPTH",
    "REDACTION_MARKER",
    "NotificationIdentityRedactor",
]
