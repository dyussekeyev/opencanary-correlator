"""Small shared helpers."""

from __future__ import annotations

from opencanary_correlator.utils.time import (
    current_time_offset,
    seconds_to_age,
    timestamp_age,
    timestamp_js,
    timestamp_printable,
    utc_now,
)

__all__ = [
    "current_time_offset",
    "seconds_to_age",
    "timestamp_age",
    "timestamp_js",
    "timestamp_printable",
    "utc_now",
]
