"""Time helpers ported from the legacy `common/utils.py`.

The originals mixed `datetime.utcnow()` with local `datetime.fromtimestamp()`,
which shifted every age by the host timezone. These versions are consistently
UTC and keep the exact output strings the console renders.
"""

from __future__ import annotations

from datetime import UTC, datetime


def utc_now() -> datetime:
    """Return the current time as an aware UTC datetime."""
    return datetime.now(UTC)


def current_time_offset() -> int:
    """Return the current Unix time as whole seconds."""
    return int(utc_now().timestamp())


def seconds_to_age(seconds: float | int) -> str:
    """Render an age as `N weeks/days/hours/minutes/seconds`, as the console does."""
    try:
        value = int(seconds)
        weeks, remainder = divmod(value, 60 * 60 * 24 * 7)
        days, remainder = divmod(remainder, 60 * 60 * 24)
        hours, remainder = divmod(remainder, 60 * 60)
        minutes, seconds_left = divmod(remainder, 60)
        if weeks > 0:
            number, unit = weeks, "week"
        elif days > 0:
            number, unit = days, "day"
        elif hours > 0:
            number, unit = hours, "hour"
        elif minutes > 0:
            number, unit = minutes, "minute"
        elif seconds_left >= 0:
            number, unit = seconds_left, "second"
        else:
            number, unit = -1, "age error"
        return f"{int(number)} {unit}{'s' if number != 1 else ''}"
    except (TypeError, ValueError):
        return "age error"


def _to_utc(timestamp: float | str) -> datetime | None:
    try:
        value = float(timestamp)
    except (TypeError, ValueError):
        return None
    try:
        return datetime.fromtimestamp(value, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None


def timestamp_age(timestamp: float | str) -> str:
    """Return a human-readable age for a Unix timestamp."""
    moment = _to_utc(timestamp)
    if moment is None:
        return "age error"
    return seconds_to_age((utc_now() - moment).total_seconds())


def timestamp_printable(timestamp: float | str) -> str:
    """Render a timestamp the way the legacy console does."""
    moment = _to_utc(timestamp)
    if moment is None:
        return str(timestamp)
    return moment.strftime("%a %b %d %Y %H:%M:%S GMT+0000 (UTC)")


def timestamp_js(timestamp: float | str) -> int:
    """Convert a Unix timestamp to JavaScript milliseconds."""
    return int(float(timestamp) * 1000)


__all__ = [
    "current_time_offset",
    "seconds_to_age",
    "timestamp_age",
    "timestamp_js",
    "timestamp_printable",
    "utc_now",
]
