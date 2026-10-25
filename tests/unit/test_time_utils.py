"""Age and timestamp rendering, which the legacy console payload depends on.

`storage/queries.py` feeds `actual_age`, `created_printable` and
`events_list_printable` from these helpers, so a change here changes what an
existing dashboard renders even when every other test is green.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from opencanary_correlator.utils import time as time_utils

STAMP = 1418997029  # 2014-12-19T13:50:29Z, the timestamp the legacy fixtures use


def test_utc_now_is_aware_utc() -> None:
    now = time_utils.utc_now()

    assert now.tzinfo is not None
    assert now.utcoffset() == timedelta(0)


def test_current_time_offset_is_whole_seconds() -> None:
    offset = time_utils.current_time_offset()

    assert isinstance(offset, int)
    assert abs(offset - int(time_utils.utc_now().timestamp())) <= 1


@pytest.mark.parametrize(
    ("seconds", "expected"),
    [
        (0, "0 seconds"),
        (1, "1 second"),
        (59, "59 seconds"),
        (60, "1 minute"),
        (120, "2 minutes"),
        (3600, "1 hour"),
        (7200, "2 hours"),
        (86400, "1 day"),
        (172800, "2 days"),
        (604800, "1 week"),
        (1209600, "2 weeks"),
        # The largest unit wins and the remainder is dropped, as in the legacy
        # console: two weeks and three days still reads "2 weeks".
        (1209600 + 3 * 86400, "2 weeks"),
        (1.9, "1 second"),
    ],
)
def test_seconds_to_age_picks_the_largest_unit(seconds, expected) -> None:
    assert time_utils.seconds_to_age(seconds) == expected


@pytest.mark.parametrize("value", ["soon", None, object()])
def test_seconds_to_age_reports_unusable_input(value) -> None:
    assert time_utils.seconds_to_age(value) == "age error"


@pytest.mark.parametrize("value", ["nope", None, "1e30"])
def test_timestamp_age_reports_unusable_input(value) -> None:
    assert time_utils.timestamp_age(value) == "age error"


def test_timestamp_age_measures_from_the_injected_now(monkeypatch) -> None:
    monkeypatch.setattr(time_utils, "utc_now", lambda: datetime.fromtimestamp(STAMP + 90, tz=UTC))

    assert time_utils.timestamp_age(STAMP) == "1 minute"
    assert time_utils.timestamp_age(str(STAMP)) == "1 minute"


def test_timestamp_printable_matches_the_legacy_console_format() -> None:
    assert time_utils.timestamp_printable(STAMP) == "Fri Dec 19 2014 13:50:29 GMT+0000 (UTC)"
    assert time_utils.timestamp_printable(str(STAMP)) == "Fri Dec 19 2014 13:50:29 GMT+0000 (UTC)"


@pytest.mark.parametrize("value", ["nope", "1e30"])
def test_timestamp_printable_falls_back_to_the_raw_value(value) -> None:
    assert time_utils.timestamp_printable(value) == value


def test_timestamp_js_converts_to_milliseconds() -> None:
    assert time_utils.timestamp_js(STAMP) == 1418997029000
    assert time_utils.timestamp_js(str(STAMP)) == 1418997029000
