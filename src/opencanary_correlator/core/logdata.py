"""Decoding of the ``logdata`` string stored on an incident.

An incident keeps the log entries it was built from as a JSON string in one
Redis hash field, because a hash cannot hold a list. Two very different readers
need it — the incident model, which merges and trims it, and the alert renderer,
which shows it to a human — and both used to carry their own decoder with
subtly different tolerance for legacy shapes. This is the single answer to
"what entries does this incident hold".

The string comes from network input, so decoding never raises: a malformed value
yields no entries rather than an exception on the alert path.
"""

from __future__ import annotations

import json
from typing import Any


def decode_logdata(raw: str | None) -> list[Any]:
    """Return the stored entries, tolerating legacy and malformed shapes.

    A list is returned as it was written. A scalar or object (an older build
    stored a single entry without the list wrapper) becomes a one-element list.
    Anything that is not JSON, and an empty value, yield an empty list.
    """
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return []
    if isinstance(parsed, list):
        return list(parsed)
    return [parsed]


__all__ = ["decode_logdata"]
