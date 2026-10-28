"""Direct unit tests for the pure rules in :mod:`opencanary_correlator.config_validation`."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import SecretStr

from opencanary_correlator import config_validation as cv


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        pytest.param(["a"], ["a"], id="non-string-passthrough"),
        pytest.param(None, None, id="none-passthrough"),
        pytest.param("", [], id="empty-string"),
        pytest.param("   ", [], id="blank-string"),
        pytest.param("a, b ,, c ", ["a", "b", "c"], id="comma-separated"),
        pytest.param('["x", "y"]', ["x", "y"], id="json-array"),
        pytest.param("[not json", ["[not json"], id="malformed-json-kept-as-item"),
    ],
)
def test_split_comma_separated(raw: Any, expected: Any) -> None:
    assert cv.split_comma_separated(raw) == expected


@pytest.mark.parametrize(
    "url",
    [
        "https://siem.example/hook",
        "http://localhost:9000/hook",
        "http://127.0.0.1/hook",
        "http://[::1]:9000/hook",
    ],
)
def test_require_http_urls_accepts_https_and_loopback_http(url: str) -> None:
    assert cv.require_http_urls([url]) == [url]


@pytest.mark.parametrize(
    "url",
    [
        "ftp://siem.example/hook",
        "file:///etc/passwd",
        "http://siem.example/hook",
    ],
)
def test_require_http_urls_rejects_non_https_remote_targets(url: str) -> None:
    # The message names the position, never the URL itself: it is printed on
    # startup and a webhook URL may carry a credential.
    with pytest.raises(ValueError, match=r"webhook_urls\[0\]"):
        cv.require_http_urls([url])


def test_require_http_urls_accepts_an_empty_list() -> None:
    assert cv.require_http_urls([]) == []


def test_validate_telegram_token_allows_none() -> None:
    assert cv.validate_telegram_token(None) is None


def test_validate_telegram_token_accepts_well_formed_token() -> None:
    token = SecretStr("123:abc_DEF-9")

    assert cv.validate_telegram_token(token) is token


@pytest.mark.parametrize("value", ["123", ":abc", "123:", "123:abc def", "abc:123x!"])
def test_validate_telegram_token_rejects_malformed_tokens(value: str) -> None:
    with pytest.raises(ValueError, match="telegram_token"):
        cv.validate_telegram_token(SecretStr(value))


def test_validate_allowed_ips_accepts_cidr_and_bare_addresses() -> None:
    entries = ["10.0.0.0/8", "192.0.2.7", "2001:db8::/32"]

    assert cv.validate_allowed_ips(entries) == entries


def test_validate_allowed_ips_rejects_invalid_entries() -> None:
    with pytest.raises(ValueError, match="invalid receiver allowlist entry"):
        cv.validate_allowed_ips(["10.0.0.0/8", "10.0.0.0/33"])


def test_health_allowlist_defaults_to_loopback_when_empty() -> None:
    assert cv.health_allowlist_or_loopback([]) == ["127.0.0.1/32", "::1/128"]


def test_health_allowlist_keeps_explicit_entries() -> None:
    assert cv.health_allowlist_or_loopback(["10.1.2.3/32"]) == ["10.1.2.3/32"]


@pytest.mark.parametrize("value", [None, ""])
def test_decode_incident_horizons_treats_missing_values_as_empty(value: Any) -> None:
    assert cv.decode_incident_horizons(value) == {}


def test_decode_incident_horizons_parses_json_object() -> None:
    assert cv.decode_incident_horizons('{"ftp.login_attempt": 300}') == {"ftp.login_attempt": 300}


def test_decode_incident_horizons_passes_dicts_through() -> None:
    value = {"ftp.login_attempt": 300}

    assert cv.decode_incident_horizons(value) is value


def test_decode_incident_horizons_rejects_malformed_json() -> None:
    with pytest.raises(ValueError, match="JSON object"):
        cv.decode_incident_horizons("{nope")


def test_validate_incident_horizons_accepts_boundary_values() -> None:
    value = {
        "ftp.login_attempt": 0.0,
        "scans.network_portscan": cv.MAX_INCIDENT_HORIZON_SECONDS,
    }

    assert cv.validate_incident_horizons(value) == value


def test_validate_incident_horizons_rejects_unknown_names_sorted() -> None:
    with pytest.raises(ValueError, match="unknown incident names") as excinfo:
        cv.validate_incident_horizons({"zzz.bogus": 1.0, "aaa.bogus": 1.0})

    assert "aaa.bogus, zzz.bogus" in str(excinfo.value)


@pytest.mark.parametrize("seconds", [-0.1, cv.MAX_INCIDENT_HORIZON_SECONDS + 1])
def test_validate_incident_horizons_rejects_out_of_range_values(seconds: float) -> None:
    with pytest.raises(ValueError, match="horizon must be between"):
        cv.validate_incident_horizons({"ftp.login_attempt": seconds})


@pytest.mark.parametrize("value", ["redis://h:6379/0", "rediss://h/1", "unix:///tmp/r.sock"])
def test_require_redis_scheme_accepts_supported_schemes(value: str) -> None:
    assert cv.require_redis_scheme(value) == value


@pytest.mark.parametrize("value", ["http://h:6379", "localhost:6379", ""])
def test_require_redis_scheme_rejects_other_schemes(value: str) -> None:
    with pytest.raises(ValueError, match="redis_url"):
        cv.require_redis_scheme(value)


def test_webhook_url_errors_do_not_echo_the_url() -> None:
    secret_url = "http://siem.example/hook/SECRETTOKEN?token=ALSOSECRET"

    with pytest.raises(ValueError) as excinfo:
        cv.require_http_urls([secret_url])

    message = str(excinfo.value)
    assert "webhook_urls[0]" in message
    assert "siem.example" in message
    assert "SECRETTOKEN" not in message
    assert "ALSOSECRET" not in message


def test_webhook_scheme_errors_name_the_scheme_only() -> None:
    with pytest.raises(ValueError) as excinfo:
        cv.require_http_urls(["ftp://user:pass@siem.example/hook"])

    message = str(excinfo.value)
    assert "'ftp'" in message
    assert "pass" not in message


def test_normalise_log_level_uppercases_strings() -> None:
    assert cv.normalise_log_level("warning") == "WARNING"


def test_normalise_log_level_passes_non_strings_through() -> None:
    assert cv.normalise_log_level(10) == 10


def test_normalise_log_level_accepts_the_short_aliases() -> None:
    assert cv.normalise_log_level("warn") == "WARNING"
    assert cv.normalise_log_level(" Fatal ") == "CRITICAL"
    # An unknown name is reported by pydantic instead of being guessed.
    assert cv.normalise_log_level("verbose") == "VERBOSE"


def test_normalise_log_file_blank_becomes_none() -> None:
    assert cv.normalise_log_file("") is None
    assert cv.normalise_log_file("   ") is None
    assert cv.normalise_log_file(None) is None
    assert cv.normalise_log_file(" /var/log/occ.log ") == "/var/log/occ.log"


@pytest.mark.parametrize("value", ["ops@example.com", "a@b"])
def test_require_email_address_accepts_local_and_domain_parts(value: str) -> None:
    assert cv.require_email_address(value) == value


@pytest.mark.parametrize("value", ["plain", "@example.com", "user@"])
def test_require_email_address_rejects_incomplete_addresses(value: str) -> None:
    with pytest.raises(ValueError, match="smtp_from"):
        cv.require_email_address(value)


@pytest.mark.parametrize("value", [None, "", "   "])
def test_normalise_health_host_defaults_to_all_interfaces(value: Any) -> None:
    assert cv.normalise_health_host(value) == cv.DEFAULT_HEALTH_HOST


def test_normalise_health_host_trims_whitespace() -> None:
    assert cv.normalise_health_host("  127.0.0.1 ") == "127.0.0.1"


@pytest.mark.parametrize("value", [None, "", "   "])
def test_disable_health_port_maps_missing_values_to_none(value: Any) -> None:
    assert cv.disable_health_port(value) is None


@pytest.mark.parametrize("value", [0, "0", " 00 ", "+0"])
def test_disable_health_port_maps_zero_to_none(value: Any) -> None:
    assert cv.disable_health_port(value) is None


@pytest.mark.parametrize(("value", "expected"), [(8080, 8080), ("9090", 9090)])
def test_disable_health_port_keeps_real_ports(value: Any, expected: int) -> None:
    assert cv.disable_health_port(value) == expected


def test_disable_health_port_leaves_unparseable_strings_for_pydantic() -> None:
    assert cv.disable_health_port("eighty") == "eighty"
