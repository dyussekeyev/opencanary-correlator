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

_CONTROL_CHARS: Final[re.Pattern[str]] = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def is_sensitive_key(key: str) -> bool:
    """Return True when a mapping key names a credential."""
    return SENSITIVE_KEY_PATTERN.search(key) is not None


def sanitize_text(value: str) -> str:
    """Strip characters that could break the JSON-per-line audit stream."""
    return _CONTROL_CHARS.sub(" ", value.replace("\r", " ").replace("\n", " "))


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
    "sanitize_text",
]
