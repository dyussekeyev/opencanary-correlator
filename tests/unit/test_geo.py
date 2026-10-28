"""Offline geo lookup: record shapes, private addresses and startup failures."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from opencanary_correlator.enrichment.geo import GeoLookup, GeoLookupError, public_address

CITY_RECORD: dict[str, Any] = {
    "country": {"iso_code": "NL", "names": {"en": "Netherlands", "de": "Niederlande"}},
    "city": {"names": {"en": "Amsterdam"}},
}
ASN_RECORD: dict[str, Any] = {
    "autonomous_system_number": 202425,
    "autonomous_system_organization": "IP Volume inc",
}


class FakeReader:
    """Stand-in for `maxminddb.open_database`."""

    def __init__(self, record: Any, *, fail: bool = False) -> None:
        self.record = record
        self.fail = fail
        self.closed = False

    def get(self, _ip: str) -> Any:
        if self.fail:
            raise RuntimeError("corrupt database")
        return self.record

    def close(self) -> None:
        self.closed = True


def test_a_public_address_gets_country_city_and_network() -> None:
    lookup = GeoLookup(FakeReader(CITY_RECORD), FakeReader(ASN_RECORD))

    info = lookup.lookup("74.22.3.178")

    assert info is not None
    assert info.country == "Netherlands"
    assert info.country_code == "NL"
    assert info.city == "Amsterdam"
    assert info.asn == 202425
    assert info.location == "Netherlands, Amsterdam"
    assert info.network == "AS202425 IP Volume inc"


@pytest.mark.parametrize("ip", ["10.0.0.5", "127.0.0.1", "::1", "169.254.1.1", "", "not-an-ip"])
def test_private_and_invalid_addresses_are_never_geolocated(ip: str) -> None:
    lookup = GeoLookup(FakeReader(CITY_RECORD))

    assert lookup.lookup(ip) is None
    assert public_address(ip) is None


def test_an_address_the_database_does_not_know_yields_nothing() -> None:
    lookup = GeoLookup(FakeReader(None), FakeReader({}))

    assert lookup.lookup("74.22.3.178") is None


def test_a_non_numeric_asn_is_ignored() -> None:
    lookup = GeoLookup(None, FakeReader({"autonomous_system_number": "AS-unknown"}))

    info = lookup.lookup("74.22.3.178")

    assert info is None


def test_a_record_that_is_not_a_mapping_is_ignored() -> None:
    lookup = GeoLookup(FakeReader("not a record"), FakeReader([1, 2, 3]))

    assert lookup.lookup("74.22.3.178") is None


def test_a_corrupt_database_does_not_break_the_alert() -> None:
    lookup = GeoLookup(FakeReader(CITY_RECORD, fail=True), FakeReader(ASN_RECORD, fail=True))

    assert lookup.lookup("74.22.3.178") is None


def test_the_asn_database_alone_still_reports_the_network() -> None:
    lookup = GeoLookup(None, FakeReader(ASN_RECORD))

    info = lookup.lookup("74.22.3.178")

    assert info is not None
    assert info.asn == 202425
    assert info.location == ""
    assert info.network == "AS202425 IP Volume inc"


def test_an_asn_number_without_a_name_still_renders() -> None:
    lookup = GeoLookup(None, FakeReader({"autonomous_system_number": 64500}))

    info = lookup.lookup("74.22.3.178")

    assert info is not None
    assert info.network == "AS64500"


def test_close_releases_both_readers() -> None:
    city = FakeReader(CITY_RECORD)
    asn = FakeReader(ASN_RECORD)
    lookup = GeoLookup(city, asn)

    lookup.close()

    assert city.closed is True
    assert asn.closed is True


def test_a_missing_file_is_a_startup_error(tmp_path: Path) -> None:
    with pytest.raises(GeoLookupError, match="no such database file"):
        GeoLookup.open(tmp_path / "absent.mmdb")


def test_no_configured_database_is_rejected() -> None:
    with pytest.raises(GeoLookupError, match="no database configured"):
        GeoLookup()
    with pytest.raises(GeoLookupError, match="no database configured"):
        GeoLookup.open()


def test_open_wires_the_readers_from_the_module(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`open` opens exactly the configured files, in order."""
    import sys
    import types

    city = tmp_path / "city.mmdb"
    asn = tmp_path / "asn.mmdb"
    city.write_bytes(b"city")
    asn.write_bytes(b"asn")
    opened: list[str] = []

    module = types.ModuleType("maxminddb")
    module.open_database = lambda path: (  # type: ignore[attr-defined]
        opened.append(path) or FakeReader(CITY_RECORD)
    )
    monkeypatch.setitem(sys.modules, "maxminddb", module)

    lookup = GeoLookup.open(city, asn)
    try:
        info = lookup.lookup("74.22.3.178")
    finally:
        lookup.close()

    assert opened == [str(city), str(asn)]
    assert info is not None and info.country == "Netherlands"


def test_open_reports_a_database_it_cannot_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import sys
    import types

    city = tmp_path / "city.mmdb"
    city.write_bytes(b"broken")

    module = types.ModuleType("maxminddb")

    def explode(_path: str) -> Any:
        raise ValueError("invalid database")

    module.open_database = explode  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "maxminddb", module)

    with pytest.raises(GeoLookupError, match="invalid database"):
        GeoLookup.open(city)


def test_the_reader_extra_is_named_in_the_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Without `maxminddb` the message has to say how to install it."""
    import builtins

    target = tmp_path / "city.mmdb"
    target.write_bytes(b"not really an mmdb")
    real_import = builtins.__import__

    def fake_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "maxminddb":
            raise ModuleNotFoundError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    with pytest.raises(GeoLookupError, match=r"opencanary-correlator\[geo\]"):
        GeoLookup.open(target)
