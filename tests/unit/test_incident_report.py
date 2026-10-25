"""Direct tests for the legacy alert templates in ``core.incident_report``.

The legacy console and operators compare these strings byte for byte, so the
expected values below are the exact output, not a loose substring match.
"""

from __future__ import annotations

from opencanary_correlator.core.incident_report import (
    render_report,
    render_report_short,
    render_scan_report,
    render_title,
)

RULE = "=" * 70
BANNER = f"\n{RULE}\n                                ALERT\n{RULE}\n\n"


def test_render_title_joins_fields_in_legacy_order() -> None:
    assert (
        render_title("FTP login attempt", "10.0.0.5", "canary-1", "10.0.0.2")
        == "FTP login attempt by 10.0.0.5 on canary-1 (10.0.0.2)"
    )


def test_render_report_matches_legacy_layout_exactly() -> None:
    text = render_report(
        description="FTP login attempt",
        created=1700000000,
        src_host="10.0.0.5",
        dst_host="10.0.0.2",
        node_id="canary-1",
        extra="  Username: admin",
    )

    assert text == (
        BANNER
        + "  Incident: FTP login attempt\n"
        + "  Time    : 2023-11-14 22:13:20 (UTC)\n"
        + "  Source  : 10.0.0.5\n"
        + "  Target  : 10.0.0.2 (id canary-1)\n"
        + "  Username: admin\n"
        + RULE
        + "\n"
    )


def test_render_report_empty_extra_leaves_blank_line() -> None:
    text = render_report(
        description="X",
        created=0,
        src_host="a",
        dst_host="b",
        node_id="n",
    )

    assert "  Target  : b (id n)\n\n" + RULE + "\n" in text
    assert text.endswith(RULE + "\n")


def test_render_report_time_is_utc_regardless_of_local_zone() -> None:
    text = render_report(
        description="X",
        created=86399,
        src_host="a",
        dst_host="b",
        node_id="n",
    )

    assert "  Time    : 1970-01-01 23:59:59 (UTC)\n" in text


def test_render_report_short_matches_legacy_one_liner() -> None:
    assert (
        render_report_short(
            description="SMB file open",
            src_host="10.0.0.5",
            node_id="canary-1",
            dst_host="10.0.0.2",
        )
        == "Canary Incident: SMB file open. Source 10.0.0.5. Target canary-1 (10.0.0.2)."
    )


def test_render_report_short_appends_extra_without_separator() -> None:
    text = render_report_short(
        description="D",
        src_host="s",
        node_id="n",
        dst_host="d",
        extra=" Extra.",
    )

    assert text == "Canary Incident: D. Source s. Target n (d). Extra."


def test_render_scan_report_matches_legacy_layout_exactly() -> None:
    text = render_scan_report(
        description="Network port scan",
        created=1700000000,
        src_host="10.0.0.5",
        dst_port=445,
        targets="10.0.0.2, 10.0.0.3",
    )

    assert text == (
        BANNER
        + "  Incident: Network port scan\n"
        + "  Time    : 1700000000\n"
        + "  Source  : 10.0.0.5\n"
        + "  Port    : 445\n"
        + "  Targets : 10.0.0.2, 10.0.0.3\n"
        + "\n"
        + RULE
        + "\n"
    )
