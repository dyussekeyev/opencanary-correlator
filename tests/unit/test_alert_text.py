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
from opencanary_correlator.enrichment.models import Enrichment, GeoInfo, VirusTotalReport


def enriched(**overrides: Any) -> Enrichment:
    """Enrichment carrying country, city, network and a VirusTotal verdict."""
    payload: dict[str, Any] = {
        "geo": GeoInfo(
            country_code="NL",
            country="Netherlands",
            city="Amsterdam",
            asn=202425,
            as_org="IP Volume inc",
        ),
        "virus_total": VirusTotalReport(
            malicious=12,
            suspicious=2,
            harmless=60,
            undetected=20,
            reputation=-34,
            checked="2026-10-26",
        ),
        "virus_total_status": "ok",
    }
    payload.update(overrides)
    return Enrichment(**payload)


def test_standard_shows_the_country_and_the_detection_ratio(incident_factory: Any) -> None:
    incident = incident_factory(enrichment=enriched())

    text = render_alert(incident, detail="standard", flavor="plain")

    assert "Location: Netherlands" in text
    # City, network and reputation belong to the detailed level.
    assert "Amsterdam" not in text
    assert "AS202425" not in text
    assert "VT: 12/94 malicious (+2 suspicious)" in text


def test_detailed_shows_city_network_and_reputation(incident_factory: Any) -> None:
    incident = incident_factory(enrichment=enriched())

    text = render_alert(incident, detail="detailed", flavor="plain")

    assert "Location: Netherlands, Amsterdam" in text
    assert "ASN: AS202425 IP Volume inc" in text
    assert "VT: 12/94 malicious (+2 suspicious), reputation -34, 2026-10-26" in text


def test_an_exhausted_quota_is_shown_as_a_status(incident_factory: Any) -> None:
    enrichment = Enrichment(
        geo=GeoInfo(country_code="NL", country="Netherlands"), virus_total_status="quota"
    )

    text = render_alert(incident_factory(enrichment=enrichment), detail="standard", flavor="plain")

    assert "VT: quota exhausted" in text
    assert "Location: Netherlands" in text


def test_an_unavailable_provider_is_shown_as_a_status(incident_factory: Any) -> None:
    enrichment = Enrichment(
        geo=GeoInfo(country_code="NL", country="Netherlands"), virus_total_status="unavailable"
    )

    text = render_alert(incident_factory(enrichment=enrichment), detail="standard", flavor="plain")

    assert "VT: unavailable" in text


def test_minimal_never_shows_enrichment(incident_factory: Any) -> None:
    incident = incident_factory(enrichment=enriched())

    text = render_alert(incident, detail="minimal", flavor="plain")

    assert text == incident.format_report_short()
    assert "Netherlands" not in text


def test_an_alert_without_enrichment_has_no_extra_rows(incident_factory: Any) -> None:
    text = render_alert(incident_factory(), detail="detailed", flavor="plain")

    assert "Location" not in text
    assert "VT:" not in text


def test_enrichment_values_cannot_forge_lines(incident_factory: Any) -> None:
    enrichment = Enrichment(geo=GeoInfo(country="NL\r\n🎯 Attacker: 6.6.6.6", city="Ams\rterdam"))

    text = render_alert(incident_factory(enrichment=enrichment), detail="detailed", flavor="plain")

    # The CRLFs collapse into spaces, so the payload stays on the Location row.
    assert "NL 🎯 Attacker: 6.6.6.6" in text
    assert sum(1 for line in text.split(CRLF) if line.startswith("🎯")) == 1


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
    # The instance address carries its port, so no second destination row repeats it.
    assert "IP: 89.126.202.164:21" in lines[3]
    assert "Destination" not in text
    assert "Attacker: 10.0.0.5:40000" in lines[5]
    assert "Time: 2014-12-19 13:50:29 UTC" in lines[6]
    assert lines[8] == "📝 Log: USERNAME=admin"
    # The instance block must come first, the attacker block after it.
    assert text.index("opencanary-embassy") < text.index("10.0.0.5")


def test_detailed_level_adds_events_and_more_log_data(incident_factory: Any) -> None:
    incident = incident_factory(
        events_count=4,
        logdata=json.dumps([{"USERNAME": "admin", "PASSWORD": "hunter2"}]),
    )

    text = render_alert(incident, detail="detailed", flavor="plain")
    lines = text.split(CRLF)

    assert "IP: 10.0.0.2:21" in text
    assert "Destination" not in text
    assert "Events: 4" in text
    assert "Log: USERNAME=admin, PASSWORD=***" in text
    assert "hunter2" not in text
    # Events and Log follow the attacker block directly, as in the requested layout.
    assert lines[-2].endswith("Events: 4")
    assert lines[-1].startswith("📝 Log:")


def test_a_destination_without_a_port_is_not_rendered_as_minus_one(incident_factory: Any) -> None:
    text = render_alert(incident_factory(dst_port=-1), detail="standard", flavor="plain")

    assert "IP: 10.0.0.2" in text
    assert "10.0.0.2:-1" not in text


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


def test_a_credential_field_is_masked_by_the_same_rule_the_audit_trail_uses(
    incident_factory: Any,
) -> None:
    """One credential list, so a field cannot be hidden in one place and shown in another.

    `redaction.SENSITIVE_KEY_PATTERN` masks anything matching `credential`, and the
    audit trail therefore hides it; the renderer used to keep its own list without
    that word and printed the value to every chat channel.
    """
    logdata = json.dumps([{"USERNAME": "admin", "PASSWORD": "hunter2", "CREDENTIAL": "abc123"}])
    for detail in ("standard", "detailed"):
        text = render_alert(incident_factory(logdata=logdata), detail=detail, flavor="plain")
        assert "hunter2" not in text
        assert "abc123" not in text
        assert "PASSWORD=***" in text
        assert "CREDENTIAL=***" in text


def test_a_credential_nested_in_a_log_entry_is_masked_too(incident_factory: Any) -> None:
    """The login rules store the event one level down, under `raw`.

    Deciding by the outer key alone printed `raw=[{"PASSWORD": "hunter2"}]` in
    every RDP, SSH and Telnet alert: the key was `raw`, the secret was inside it.
    """
    logdata = json.dumps([{"raw": [{"USERNAME": "administrator", "PASSWORD": "hunter2"}]}])

    for detail in ("standard", "detailed"):
        text = render_alert(incident_factory(logdata=logdata), detail=detail, flavor="plain")

        assert "hunter2" not in text
        assert "PASSWORD=***" in text
        # The non-secret part of the same entry is still shown, and the wrapper
        # the login rules add does not reach the alert.
        assert "USERNAME=administrator" in text
        assert "raw=" not in text


def test_a_corrupt_timestamp_renders_unknown_instead_of_crashing(incident_factory: Any) -> None:
    """`created` comes from an event field, so it can be out of the calendar range.

    Rendering must degrade to "unknown": an exception here would drop the whole
    alert for every channel at once.
    """
    text = render_alert(incident_factory(created=99999999999999), detail="standard", flavor="plain")

    assert "Time: unknown" in text


def test_an_incident_without_a_destination_host_shows_unknown(incident_factory: Any) -> None:
    text = render_alert(incident_factory(dst_host=""), detail="standard", flavor="plain")

    assert "IP: unknown:21" in text


def test_a_geo_guess_without_a_country_name_falls_back_to_the_code(incident_factory: Any) -> None:
    """MaxMind sometimes has the code but not the display name."""
    enrichment = Enrichment(geo=GeoInfo(country_code="NL"))

    text = render_alert(incident_factory(enrichment=enrichment), detail="standard", flavor="plain")

    assert "Location: NL" in text


def test_a_report_without_a_reputation_or_a_date_still_renders_the_ratio(
    incident_factory: Any,
) -> None:
    enrichment = Enrichment(
        virus_total=VirusTotalReport(malicious=0, suspicious=0, harmless=70, undetected=24),
        virus_total_status="ok",
    )

    text = render_alert(incident_factory(enrichment=enrichment), detail="detailed", flavor="plain")

    assert "VT: 0/94 malicious" in text
    # No "reputation None" or "None" leaking into the row.
    assert "None" not in text


def test_a_log_entry_shows_at_most_six_fields(incident_factory: Any) -> None:
    """The row has to stay one line on a phone; the cap is what keeps it there."""
    logdata = json.dumps([{f"KEY{index}": index for index in range(8)}])

    text = render_alert(incident_factory(logdata=logdata), detail="detailed", flavor="plain")

    assert "KEY5=5" in text
    assert "KEY6=6" not in text


def test_a_list_inside_log_data_is_rendered_as_text_not_dropped() -> None:
    """A scan stores its evidence as a list; a mixed payload must not lose entries."""
    summary = log_summary(json.dumps([[21, 22], {"USERNAME": "admin"}]))

    assert summary == "[21, 22] | USERNAME=admin"


def test_a_nested_log_value_is_rendered_as_json(incident_factory: Any) -> None:
    """A log field can hold a structure; it must be shown, not dropped or crashed on."""
    logdata = json.dumps([{"details": {"PORT": 22, "PROTO": "tcp"}}])

    text = render_alert(incident_factory(logdata=logdata), detail="detailed", flavor="plain")

    assert 'details={"PORT": 22, "PROTO": "tcp"}' in text


def test_a_raw_mapping_without_a_list_wrapper_is_unwrapped(incident_factory: Any) -> None:
    """Older events store `raw` as a bare object instead of a one-element list."""
    logdata = json.dumps([{"raw": {"USERNAME": "admin"}}])

    text = render_alert(incident_factory(logdata=logdata), detail="standard", flavor="plain")

    assert "Log: USERNAME=admin" in text
    assert "raw=" not in text


def test_an_empty_raw_wrapper_renders_no_log_row(incident_factory: Any) -> None:
    logdata = json.dumps([{"raw": {}}])

    text = render_alert(incident_factory(logdata=logdata), detail="standard", flavor="plain")

    assert "📝" not in text


def test_an_incident_without_log_data_has_no_log_row(incident_factory: Any) -> None:
    """Not every rule captures evidence; an empty row would look like a parsing failure."""
    text = render_alert(incident_factory(logdata=None), detail="standard", flavor="plain")

    assert "📝" not in text


def test_an_empty_geo_object_adds_no_location_row(incident_factory: Any) -> None:
    """A cached geo entry with no usable fields must not print an empty value."""
    text = render_alert(
        incident_factory(enrichment=Enrichment(geo=GeoInfo())), detail="standard", flavor="plain"
    )

    assert "Location" not in text
    assert "📍" not in text
