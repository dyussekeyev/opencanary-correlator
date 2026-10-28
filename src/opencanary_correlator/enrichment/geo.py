"""Offline country/city/ASN lookup from MMDB files.

The correlator reads a local database instead of calling a geolocation API: no
key, no quota, and the address of an attacker is never disclosed to a third
party. Both DB-IP Lite and MaxMind GeoLite2 publish files in this format, so the
same reader serves either.

The reader is an optional dependency (`pip install
"opencanary-correlator[geo]"`), imported lazily so a deployment that does not
configure a database never needs it.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any, Final

from opencanary_correlator.enrichment.models import GeoInfo

#: DB-IP and MaxMind both name the English name first; fall back to the code.
_ENGLISH: Final[str] = "en"
_INSTALL_HINT: Final[str] = (
    "the geo extra is required: pip install 'opencanary-correlator[geo]' "
    "(or rebuild the image, which installs it)"
)


class GeoLookupError(RuntimeError):
    """Raised when a configured database cannot be opened."""


def _name(names: Any, fallback: str = "") -> str:
    """Return the English name from an MMDB `names` map."""
    if not isinstance(names, dict):
        return fallback
    value = names.get(_ENGLISH) or next(iter(names.values()), "")
    return str(value) if value else fallback


class GeoLookup:
    """Look up country, city and network of an address in local MMDB files."""

    def __init__(self, city_reader: Any | None = None, asn_reader: Any | None = None) -> None:
        if city_reader is None and asn_reader is None:
            raise GeoLookupError("no database configured")
        self._city_reader = city_reader
        self._asn_reader = asn_reader

    @classmethod
    def open(
        cls,
        city_db: str | Path | None = None,
        asn_db: str | Path | None = None,
    ) -> GeoLookup:
        """Open the configured databases, raising :class:`GeoLookupError` on failure.

        A misconfigured path is a startup error on purpose: silently enriching
        nothing is indistinguishable from a database that found no data.
        """
        if not city_db and not asn_db:
            raise GeoLookupError("no database configured")
        paths = [Path(path).expanduser() for path in (city_db, asn_db) if path]
        for target in paths:
            # The path is checked before the import so a typo is reported as a
            # typo, even in a deployment that never installed the extra.
            if not target.is_file():
                raise GeoLookupError(f"no such database file: {target}")

        try:
            import maxminddb
        except ModuleNotFoundError as exc:  # pragma: no cover - exercised via monkeypatch
            raise GeoLookupError(_INSTALL_HINT) from exc

        def reader(path: str | Path) -> Any:
            target = Path(path).expanduser()
            try:
                return maxminddb.open_database(str(target))
            except Exception as exc:  # maxminddb raises its own error hierarchy
                raise GeoLookupError(f"{target}: {exc}") from exc

        city_reader = reader(city_db) if city_db else None
        asn_reader = reader(asn_db) if asn_db else None
        return cls(city_reader, asn_reader)

    def close(self) -> None:
        """Close the underlying readers."""
        for reader in (self._city_reader, self._asn_reader):
            close = getattr(reader, "close", None)
            if callable(close):
                close()

    def lookup(self, ip: str) -> GeoInfo | None:
        """Return the geo data for `ip`, or None for private/invalid addresses."""
        address = public_address(ip)
        if address is None:
            return None
        city = self._city_record(address)
        asn = self._asn_record(address)
        info = GeoInfo(
            country_code=str(city.get("country_code") or ""),
            country=str(city.get("country") or ""),
            city=str(city.get("city") or ""),
            asn=asn.get("asn"),
            as_org=str(asn.get("as_org") or ""),
        )
        return None if info.is_empty else info

    # --- Record shapes ------------------------------------------------------

    def _city_record(
        self, address: ipaddress.IPv4Address | ipaddress.IPv6Address
    ) -> dict[str, Any]:
        """Flatten a DB-IP/GeoLite2 city record into plain strings."""
        if self._city_reader is None:
            return {}
        try:
            record = self._city_reader.get(str(address))
        except Exception:  # a corrupt database must not fail the alert
            return {}
        if not isinstance(record, dict):
            return {}
        raw_country = record.get("country")
        raw_city = record.get("city")
        country: dict[str, Any] = raw_country if isinstance(raw_country, dict) else {}
        city: dict[str, Any] = raw_city if isinstance(raw_city, dict) else {}
        return {
            "country_code": country.get("iso_code", ""),
            "country": _name(country.get("names")),
            "city": _name(city.get("names")),
        }

    def _asn_record(self, address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> dict[str, Any]:
        """Read the ASN number and organisation from the ASN database."""
        if self._asn_reader is None:
            return {}
        try:
            record = self._asn_reader.get(str(address))
        except Exception:  # a corrupt database must not fail the alert
            return {}
        if not isinstance(record, dict):
            return {}
        number = record.get("autonomous_system_number")
        organisation = record.get("autonomous_system_organization") or ""
        try:
            asn = int(number) if number is not None else None
        except (TypeError, ValueError):
            asn = None
        return {"asn": asn, "as_org": str(organisation)}


def public_address(ip: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse `ip`, returning None unless it is a globally routable address.

    A honeypot event can carry `10.0.0.5` or an empty host; geolocating those
    would put a wrong country on the alert.
    """
    try:
        address = ipaddress.ip_address(ip.strip())
    except (AttributeError, ValueError):
        return None
    return address if address.is_global else None


__all__ = ["GeoLookup", "GeoLookupError", "public_address"]
