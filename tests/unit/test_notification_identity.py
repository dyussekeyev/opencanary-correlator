"""Outbound honeypot-identity redaction: matching, boundaries and payload copies."""

from __future__ import annotations

from typing import Any

from opencanary_correlator.notification_identity import (
    REDACTION_MARKER,
    NotificationIdentityRedactor,
)

PROTECTED_IP = "203.0.113.10"
PROTECTED_DOMAIN = "canary.example.test"


def test_an_ip_is_removed_from_a_log_field_and_a_url() -> None:
    redactor = NotificationIdentityRedactor([PROTECTED_IP])

    text = redactor.text(
        f"HOSTNAME={PROTECTED_IP}, URL=https://{PROTECTED_IP}:8443/admin, "
        f"source={PROTECTED_IP}:52344"
    )

    assert PROTECTED_IP not in text
    assert text.count(REDACTION_MARKER) == 3
    assert f"HOSTNAME={REDACTION_MARKER}" in text
    assert f"https://{REDACTION_MARKER}:8443/admin" in text
    assert f"source={REDACTION_MARKER}:52344" in text


def test_an_ip_is_not_matched_inside_a_longer_address() -> None:
    redactor = NotificationIdentityRedactor([PROTECTED_IP])

    text = redactor.text("110.0.0.5 203.0.113.100 203.0.113.10.5")

    assert text == "110.0.0.5 203.0.113.100 203.0.113.10.5"


def test_a_domain_is_removed_case_insensitively_with_subdomains() -> None:
    redactor = NotificationIdentityRedactor([PROTECTED_DOMAIN])

    text = redactor.text(
        f"HOST={PROTECTED_DOMAIN} host={PROTECTED_DOMAIN.upper()} "
        f"url=https://www.{PROTECTED_DOMAIN}/login"
    )

    assert PROTECTED_DOMAIN not in text.lower()
    assert f"HOST={REDACTION_MARKER}" in text
    assert f"host={REDACTION_MARKER}" in text
    assert f"url=https://{REDACTION_MARKER}/login" in text


def test_a_domain_is_not_matched_inside_an_unrelated_name() -> None:
    redactor = NotificationIdentityRedactor([PROTECTED_DOMAIN])

    text = redactor.text("notcanary.example.test canary.example.test.evil.test")

    # The first is a different host; the second legitimately contains the
    # protected name as a suffix, which is still the operator's identity.
    assert text.startswith("notcanary.example.test")
    assert "canary.example.test.evil.test" not in text


def test_markdownv2_escapes_do_not_defeat_the_match() -> None:
    """Telegram escapes `.` and `-`; the filter runs after that rendering."""
    redactor = NotificationIdentityRedactor([PROTECTED_IP, PROTECTED_DOMAIN])

    text = redactor.text(
        r"HOSTNAME=203\.0\.113\.10, HOST=canary\.example\.test, "
        r"UA=my\-agent.canary\.example\.test"
    )

    assert r"203\.0\.113\.10" not in text
    assert r"canary\.example\.test" not in text
    assert text.count(REDACTION_MARKER) == 3


def test_an_ipv6_literal_is_matched_as_a_token() -> None:
    redactor = NotificationIdentityRedactor(["2001:db8::10"])

    text = redactor.text("HOST=2001:DB8::10 and 2001:db8::100")

    assert f"HOST={REDACTION_MARKER}" in text
    assert "2001:db8::100" in text


def test_the_marker_is_safe_inside_rendered_chat_markup() -> None:
    """The filter runs after MarkdownV2 escaping, so the marker must not need it."""
    assert REDACTION_MARKER
    assert not set(REDACTION_MARKER) & set("_*[]()~`>#+-=|{}.!\\")


def test_an_empty_filter_is_a_byte_identical_no_op() -> None:
    redactor = NotificationIdentityRedactor([])

    assert redactor.enabled is False
    assert redactor.text(f"{PROTECTED_IP} {PROTECTED_DOMAIN}") == (
        f"{PROTECTED_IP} {PROTECTED_DOMAIN}"
    )
    payload: dict[str, Any] = {"text": PROTECTED_IP, "nested": [PROTECTED_DOMAIN]}
    assert redactor.payload(payload) == payload


def test_a_payload_is_scrubbed_recursively_without_mutating_the_original() -> None:
    redactor = NotificationIdentityRedactor([PROTECTED_IP, PROTECTED_DOMAIN])
    original: dict[str, Any] = {
        "title": f"Probe from {PROTECTED_IP}",
        "text": f"HOSTNAME={PROTECTED_IP}",
        "enrichment": {
            "geo": {"city": PROTECTED_DOMAIN},
            "labels": [PROTECTED_DOMAIN, "unchanged"],
        },
        "count": 3,
    }

    scrubbed = redactor.payload(original)

    assert PROTECTED_IP not in str(scrubbed)
    assert PROTECTED_DOMAIN not in str(scrubbed)
    assert scrubbed["enrichment"]["labels"] == [REDACTION_MARKER, "unchanged"]
    assert scrubbed["count"] == 3
    # The incident/document the caller holds must stay intact.
    assert original["text"] == f"HOSTNAME={PROTECTED_IP}"
    assert original["enrichment"]["geo"]["city"] == PROTECTED_DOMAIN
