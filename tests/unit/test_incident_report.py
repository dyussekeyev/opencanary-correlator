"""Direct tests for the legacy alert templates in ``core.incident_report``.

The legacy console and operators compare these strings byte for byte, so the
expected values below are the exact output, not a loose substring match. The one
deliberate 0.7.0 change is the removed honeypot address: every other byte of the
legacy layout stays where it was.
"""

from __future__ import annotations

from inspect import signature

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
        render_title("FTP login attempt", "10.0.0.5", "canary-1")
        == "FTP login attempt by 10.0.0.5 on canary-1"
    )


def test_render_report_matches_legacy_layout_exactly() -> None:
    text = render_report(
        description="FTP login attempt",
        created=1700000000,
        src_host="10.0.0.5",
        node_id="canary-1",
        extra="  Username: admin",
    )

    assert text == (
        BANNER
        + "  Incident: FTP login attempt\n"
        + "  Time    : 2023-11-14 22:13:20 (UTC)\n"
        + "  Source  : 10.0.0.5\n"
        + "  Target  : canary-1\n"
        + "  Username: admin\n"
        + RULE
        + "\n"
    )


def test_render_report_empty_extra_leaves_blank_line() -> None:
    text = render_report(description="X", created=0, src_host="a", node_id="n")

    assert "  Target  : n\n\n" + RULE + "\n" in text
    assert text.endswith(RULE + "\n")


def test_render_report_time_is_utc_regardless_of_local_zone() -> None:
    text = render_report(description="X", created=86399, src_host="a", node_id="n")

    assert "  Time    : 1970-01-01 23:59:59 (UTC)\n" in text


def test_render_report_short_matches_legacy_one_liner() -> None:
    assert (
        render_report_short(description="SMB file open", src_host="10.0.0.5", node_id="canary-1")
        == "Canary Incident: SMB file open. Source 10.0.0.5. Target canary-1."
    )


def test_render_report_short_appends_extra_without_separator() -> None:
    text = render_report_short(description="D", src_host="s", node_id="n", extra=" Extra.")

    assert text == "Canary Incident: D. Source s. Target n. Extra."


def test_render_scan_report_counts_targets_without_naming_them() -> None:
    text = render_scan_report(
        description="Network port scan",
        created=1700000000,
        src_host="10.0.0.5",
        dst_port=445,
        targets=2,
    )

    assert text == (
        BANNER
        + "  Incident: Network port scan\n"
        + "  Time    : 1700000000\n"
        + "  Source  : 10.0.0.5\n"
        + "  Port    : 445\n"
        + "  Targets : 2 hosts\n"
        + "\n"
        + RULE
        + "\n"
    )


def test_a_single_scan_target_is_singular() -> None:
    text = render_scan_report(
        description="Network port scan", created=0, src_host="s", dst_port=1, targets=1
    )

    assert "  Targets : 1 host\n" in text


def test_no_template_accepts_a_honeypot_address() -> None:
    """Defence in depth: the address cannot leak back in through a parameter."""
    for func in (render_title, render_report, render_report_short):
        assert "dst_host" not in signature(func).parameters
