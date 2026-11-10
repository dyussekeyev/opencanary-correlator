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
from collections.abc import Iterable, Mapping, Sequence
from typing import Any, Final

#: Replacement for a protected identity. Plain letters on purpose: the filter
#: runs on the finished payload, after Telegram's MarkdownV2 escaping, so a
#: marker containing `*`, `[` or `_` would itself be rejected as unescaped.
REDACTION_MARKER: Final[str] = "REDACTED"

#: Guards against pathological nesting in a payload assembled from network input.
MAX_REDACTION_DEPTH: Final[int] = 16

#: A URL-encoded value can itself be encoded again (`%252E`). Two passes cover
#: the realistic variants without letting a crafted `%25` chain grow the work.
MAX_PERCENT_DECODE_PASSES: Final[int] = 2

_HEX_DIGITS: Final[frozenset[str]] = frozenset("0123456789abcdefABCDEF")

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
        """Return ``value`` with every protected identity replaced.

        Plain text takes the direct path. A value containing ``%`` is also
        checked through one or two percent-decoded views, because an attacker
        can encode the dots, hyphens or every character of the honeypot's own
        address. Matches are mapped back to the original spans, so the output
        keeps the surrounding punctuation and escapes byte-for-byte; only the
        protected token becomes the marker.
        """
        if not self._patterns or not value:
            return value
        if "%" not in value:
            for pattern in self._patterns:
                value = pattern.sub(REDACTION_MARKER, value)
            return value

        spans: list[tuple[int, int]] = []
        for decoded, mapping in _percent_decoded_views(value):
            for pattern in self._patterns:
                for match in pattern.finditer(decoded):
                    spans.append((mapping[match.start()][0], mapping[match.end() - 1][1]))
        return _replace_spans(value, spans)

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


def _percent_decode(
    text: str, source_spans: Sequence[tuple[int, int]]
) -> tuple[str, list[tuple[int, int]]]:
    """Decode one layer of ``%XX`` escapes, keeping a span per output character."""
    characters: list[str] = []
    spans: list[tuple[int, int]] = []
    index = 0
    while index < len(text):
        if (
            text[index] == "%"
            and index + 2 < len(text)
            and text[index + 1] in _HEX_DIGITS
            and text[index + 2] in _HEX_DIGITS
        ):
            characters.append(chr(int(text[index + 1 : index + 3], 16)))
            spans.append((source_spans[index][0], source_spans[index + 2][1]))
            index += 3
        else:
            characters.append(text[index])
            spans.append(source_spans[index])
            index += 1
    return "".join(characters), spans


def _percent_decoded_views(value: str) -> list[tuple[str, list[tuple[int, int]]]]:
    """Return the original and up to two percent-decoded views of ``value``.

    Each decoded character carries the original half-open span it came from, so
    a match on the decoded view can replace exactly the encoded source text.
    """
    views: list[tuple[str, list[tuple[int, int]]]] = [
        (value, [(index, index + 1) for index in range(len(value))])
    ]
    current = value
    for _ in range(MAX_PERCENT_DECODE_PASSES):
        decoded, spans = _percent_decode(current, views[-1][1])
        if decoded == current:
            break
        views.append((decoded, spans))
        current = decoded
    return views


def _replace_spans(value: str, spans: Iterable[tuple[int, int]]) -> str:
    """Replace merged source spans with the marker, preserving everything else."""
    ordered = sorted(spans)
    if not ordered:
        return value
    merged: list[tuple[int, int]] = []
    for start, end in ordered:
        if merged and start <= merged[-1][1]:
            previous_start, previous_end = merged[-1]
            merged[-1] = (previous_start, max(previous_end, end))
        else:
            merged.append((start, end))

    pieces: list[str] = []
    cursor = 0
    for start, end in merged:
        pieces.append(value[cursor:start])
        pieces.append(REDACTION_MARKER)
        cursor = end
    pieces.append(value[cursor:])
    return "".join(pieces)


def _is_ip(value: str) -> bool:
    """True when a normalised value is an IP literal rather than a DNS name."""
    return ":" in value or value.replace(".", "").isdigit()


__all__ = [
    "MAX_REDACTION_DEPTH",
    "REDACTION_MARKER",
    "NotificationIdentityRedactor",
]
