"""Rendering of alert messages: detail levels, markup, sanitising and masking."""

from __future__ import annotations

import json
from typing import Any

from opencanary_correlator.connectors.dispatchers.alert_text import (
    CRLF,
    clip,
    log_summary,
    render_alert,
)


def test_minimal_level_is_the_legacy_one_liner(incident_factory: Any) -> None:
    incident = incident_factory()

    text = render_alert(incident, detail="minimal", flavor="telegram")

    assert text == incident.format_report_short()
    assert "Canary Incident: FTP Login Attempt." in text
    assert CRLF not in text


def test_standard_level_puts_the_instance_before_the_attacker(incident_factory: Any) -> None:
    incident = incident_factory(node_id="opencanary-embassy", dst_host="89.126.202.164")

    text = render_alert(incident, detail="standard", flavor="plain")
    lines = text.split(CRLF)

    assert lines[0] == "OpenCanary: FTP Login Attempt"
    assert "Instance: opencanary-embassy" in lines[2]
    assert "IP: 89.126.202.164" in lines[3]
    assert "Attacker: 10.0.0.5:40000" in lines[5]
    assert "Time: 2014-12-19 13:50:29 UTC" in lines[6]
    assert lines[8] == "📝 Log: USERNAME=admin"
    # The instance block must come first, the attacker block after it.
    assert text.index("opencanary-embassy") < text.index("10.0.0.5")


def test_detailed_level_adds_destination_events_and_log(incident_factory: Any) -> None:
    incident = incident_factory(
        events_count=4,
        logdata=json.dumps([{"USERNAME": "admin", "PASSWORD": "hunter2"}]),
    )

    text = render_alert(incident, detail="detailed", flavor="plain")

    assert "Destination: 10.0.0.2:21" in text
    assert "Events: 4" in text
    assert "Log: USERNAME=admin, PASSWORD=***" in text
    assert "hunter2" not in text


def test_credentials_are_masked_for_every_incident_shape(incident_factory: Any) -> None:
    secret_log = json.dumps(
        [{"USERNAME": "root", "PASSWORD": "s3cret", "API_TOKEN": "abc", "note": "ok"}]
    )

    text = render_alert(incident_factory(logdata=secret_log), detail="detailed", flavor="plain")

    assert "s3cret" not in text
    assert "abc" not in text
    assert "USERNAME=root" in text
    assert "PASSWORD=***" in text
    assert "API_TOKEN=***" in text
    assert "note=ok" in text


def test_control_characters_cannot_forge_extra_lines(incident_factory: Any) -> None:
    incident = incident_factory(node_id="canary\r\n🎯 Attacker: 6.6.6.6")

    text = render_alert(incident, detail="standard", flavor="plain")

    assert len(text.split(CRLF)) == 9
    assert "canary 🎯 Attacker: 6.6.6.6" in text


def test_telegram_markup_escapes_reserved_characters(incident_factory: Any) -> None:
    incident = incident_factory(description="FTP (Login) Attempt!", dst_host="10.0.0.2")

    text = render_alert(incident, detail="standard", flavor="telegram")

    assert "*FTP \\(Login\\) Attempt\\!*" in text
    assert "*Instance:*" in text
    assert "10\\.0\\.0\\.2" in text


def test_slack_markup_escapes_html_entities(incident_factory: Any) -> None:
    incident = incident_factory(node_id="canary <lab> & co")

    text = render_alert(incident, detail="standard", flavor="slack")

    assert "*Instance:* canary &lt;lab&gt; &amp; co" in text


def test_discord_markup_uses_double_asterisks(incident_factory: Any) -> None:
    text = render_alert(incident_factory(), detail="standard", flavor="discord")

    assert text.startswith("🛡 OpenCanary: **FTP Login Attempt**")
    assert "**Attacker:** 10.0.0.5:40000" in text


def test_standard_shows_one_log_entry_and_detailed_shows_more(incident_factory: Any) -> None:
    logdata = json.dumps([{"USERNAME": f"user{index}"} for index in range(3)])
    incident = incident_factory(logdata=logdata)

    standard = render_alert(incident, detail="standard", flavor="plain")
    detailed = render_alert(incident, detail="detailed", flavor="plain")

    assert "user0" in standard
    assert "user1" not in standard
    assert "user0" in detailed
    assert "user2" in detailed


def test_scan_log_data_is_summarised_as_a_list() -> None:
    logdata = json.dumps([21, 22, 23, 80, 443, 8080, 8443, 9000, 9001, 9100, 9200])

    summary = log_summary(logdata)

    assert summary.startswith("21, 22, 23, 80, 443")
    assert summary.endswith("(+1 more)")


def test_log_summary_tolerates_missing_or_broken_data() -> None:
    assert log_summary(None) == ""
    assert log_summary("not json") == ""
    assert log_summary(json.dumps([])) == ""


def test_clip_never_leaves_a_dangling_escape() -> None:
    text = "a" * 10 + "\\" * 3 + "tail"

    clipped = clip(text, 12)

    assert len(clipped) <= 12
    assert clipped.endswith("…")
    assert not clipped[:-1].endswith("\\")


def test_max_length_is_honoured(incident_factory: Any) -> None:
    text = render_alert(incident_factory(), detail="detailed", flavor="telegram", max_length=20)

    assert len(text) == 20
    assert text.endswith("…")
