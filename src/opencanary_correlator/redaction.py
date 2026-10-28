"""Secret redaction and log-injection defence for audit records.

Honeypot payloads are attacker-controlled: `logdata` may contain passwords that
the canary captured, and any string may contain CR/LF or NUL bytes intended to
forge log lines. Everything written to the audit trail passes through here
first.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any, Final

REDACTION_MARKER: Final[str] = "***"

#: Keys whose values are never written to audit output.
SENSITIVE_KEY_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"(?i)(pass(word|wd)?|secret|token|api[_-]?key|auth|credential|private[_-]?key)"
)

#: Guards against pathological nesting coming from a malicious payload.
MAX_REDACTION_DEPTH: Final[int] = 8

#: C0 controls, DEL and the Unicode line/paragraph separators. `str.splitlines()`
#: and several log shippers treat U+0085, U+2028 and U+2029 as line breaks, so they
#: can forge a line in a file that a collector ingests even though the record has
#: no CR/LF.
_CONTROL_CHARS: Final[re.Pattern[str]] = re.compile(
    r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u0085\u2028\u2029]"
)

#: Credentials embedded in URLs, which libraries log verbatim.
#:
#: ``httpx`` writes ``HTTP Request: POST <url>`` at INFO for every delivery, and
#: the Telegram Bot API only accepts the token as part of the path — there is no
#: header or body alternative. Slack and Discord webhook URLs carry their secret
#: in the path too, and Redis/Vault-style URLs may carry a password.
_URL_SECRET_PATTERNS: Final[tuple[tuple[re.Pattern[str], str], ...]] = (
    (re.compile(r"(api\.telegram\.org/bot)\d+:[A-Za-z0-9_-]+"), r"\1***"),
    (re.compile(r"(hooks\.slack\.com/services/)[A-Za-z0-9/_-]+"), r"\1***"),
    (re.compile(r"(discord(?:app)?\.com/api/webhooks/)[A-Za-z0-9/_-]+"), r"\1***"),
    (re.compile(r"([a-zA-Z][a-zA-Z0-9+.-]*://[^:/\s@]*:)[^@/\s]+@"), r"\1***@"),
    # Generic webhooks (SIEM shims, chat bridges) often carry their credential in
    # the query string, where `httpx` logs it verbatim.
    (
        re.compile(
            r"(?i)([?&](?:access[_-]?token|token|api[_-]?key|key|secret|password|passwd"
            r"|signature|sig|auth|credential)=)[^&\s#]+"
        ),
        r"\1***",
    ),
)


def is_sensitive_key(key: str) -> bool:
    """Return True when a mapping key names a credential."""
    return SENSITIVE_KEY_PATTERN.search(key) is not None


def sanitize_text(
    value: object,
    *,
    limit: int | None = None,
    collapse: bool = False,
) -> str:
    """Turn a value into one printable line, optionally flattened and clipped.

    Two callers need different things from the same character set: the audit
    stream must keep a value intact apart from the line breaks that would split a
    record (``limit=None``, ``collapse=False``), while an alert row is flattened
    and clipped to fit a chat message. Keeping one implementation stops the two
    from drifting, which is how `CREDENTIAL` stayed visible in chat and hidden in
    the audit trail when each side owned its own list and its own stripper.
    """
    text = _CONTROL_CHARS.sub(" ", str(value).replace("\r", " ").replace("\n", " "))
    if collapse:
        text = " ".join(text.split())
    if limit is not None and len(text) > limit:
        text = text[: max(0, limit - 1)] + "…"
    return text


def redact_url_secrets(text: str) -> str:
    """Mask credentials embedded in URLs inside free text.

    Applied to log messages: `httpx` logs the full request URL at INFO, so a
    Telegram bot token, a Slack/Discord webhook path or a Redis password would
    reach stderr, the rotated log file and any collector reading them.
    """
    for pattern, replacement in _URL_SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def redact(value: Any, *, _depth: int = 0) -> Any:
    """Return a copy of `value` with credentials masked and text sanitised."""
    if _depth > MAX_REDACTION_DEPTH:
        return REDACTION_MARKER
    if isinstance(value, Mapping):
        return {
            sanitize_text(str(key)): (
                REDACTION_MARKER if is_sensitive_key(str(key)) else redact(item, _depth=_depth + 1)
            )
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple, set, frozenset)):
        return [redact(item, _depth=_depth + 1) for item in value]
    if isinstance(value, str):
        return sanitize_text(value)
    return value


def redact_mapping(value: Mapping[str, Any]) -> dict[str, Any]:
    """Redact a mapping, returning a plain dict safe for JSON serialisation."""
    redacted = redact(value)
    assert isinstance(redacted, dict)  # noqa: S101 - invariant of redact()
    return redacted


__all__ = [
    "MAX_REDACTION_DEPTH",
    "REDACTION_MARKER",
    "SENSITIVE_KEY_PATTERN",
    "is_sensitive_key",
    "redact",
    "redact_mapping",
    "redact_url_secrets",
    "sanitize_text",
]
