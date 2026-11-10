"""Small async MISP Automation API client.

Only the endpoints the publisher needs are implemented. Redirects are refused:
an API key in an ``Authorization`` header must not be replayed to a host MISP did
not name. Response bodies are bounded before JSON parsing, and error messages
carry a status and reason rather than a URL, response body or credential.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Sequence
from typing import Any, Final, cast
from urllib.parse import quote
from uuid import UUID

import httpx

from opencanary_correlator.connectors.publishers.misp.models import (
    MispAttribute,
    MispEvent,
    MispExistingAttribute,
    MispExistingEvent,
)

_DEFAULT_MAX_RESPONSE_BYTES: Final[int] = 2 * 1024 * 1024
_RETRYABLE_STATUSES: Final[frozenset[int]] = frozenset({408, 425, 429, 500, 502, 503, 504})


class MispClientError(RuntimeError):
    """A MISP call failed. The message is safe to log."""

    def __init__(
        self, reason: str, *, status_code: int | None = None, retryable: bool = False
    ) -> None:
        self.reason = reason
        self.status_code = status_code
        self.retryable = retryable
        suffix = f" (HTTP {status_code})" if status_code is not None else ""
        super().__init__(f"{reason}{suffix}")


class MispAuthError(MispClientError):
    """The API key was rejected or is not allowed to perform the operation."""


class MispNotFoundError(MispClientError):
    """The requested MISP object does not exist."""


def _object(value: Any, *, reason: str = "invalid_response") -> dict[str, Any]:
    if not isinstance(value, dict):
        raise MispClientError(reason)
    return cast(dict[str, Any], value)


def _list(value: Any, *, key: str) -> list[Any]:
    if isinstance(value, dict):
        value = value.get(key, [])
    if not isinstance(value, list):
        raise MispClientError("invalid_response")
    return value


class MispClient:
    """Minimal MISP API surface used by :class:`MispPublisher`."""

    def __init__(
        self,
        *,
        url: str,
        api_key: str,
        verify_tls: bool = True,
        timeout: float = 10.0,
        max_response_bytes: int = _DEFAULT_MAX_RESPONSE_BYTES,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._base_url = url.rstrip("/")
        self._api_key = api_key
        self._max_response_bytes = max_response_bytes
        self._client = client or httpx.AsyncClient(
            timeout=timeout,
            verify=verify_tls,
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
        )
        self._owns_client = client is None
        self._headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": api_key,
        }

    async def __aenter__(self) -> MispClient:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    def _url(self, path: str) -> str:
        return f"{self._base_url}/{path.lstrip('/')}"

    async def _request(
        self,
        method: str,
        path: str,
        *,
        payload: Any | None = None,
        not_found_ok: bool = False,
    ) -> Any:
        try:
            pending = self._client.request(
                method,
                self._url(path),
                headers=self._headers,
                json=payload,
                follow_redirects=False,
            )
            response = await cast(Awaitable[httpx.Response], pending)
        except httpx.HTTPError as exc:
            raise MispClientError("transport_error", retryable=True) from exc

        if response.status_code == 404 and not_found_ok:
            raise MispNotFoundError("not_found", status_code=404)
        if response.status_code in {401, 403}:
            raise MispAuthError("unauthorized", status_code=response.status_code, retryable=False)
        if response.status_code < 200 or response.status_code >= 300:
            raise MispClientError(
                "http_error",
                status_code=response.status_code,
                retryable=response.status_code in _RETRYABLE_STATUSES,
            )
        declared = response.headers.get("content-length")
        if declared is not None:
            try:
                if int(declared) > self._max_response_bytes:
                    raise MispClientError("response_too_large")
            except ValueError:
                pass
        if len(response.content) > self._max_response_bytes:
            raise MispClientError("response_too_large")
        try:
            return response.json()
        except (json.JSONDecodeError, ValueError) as exc:
            raise MispClientError("invalid_response") from exc

    async def add_event(self, event: MispEvent) -> tuple[int, UUID]:
        """Create an event and return its numeric id and UUID."""
        response = await self._request("POST", "events/add", payload={"Event": event.payload()})
        box = _object(response)
        raw_event = box.get("Event", box)
        created = _object(raw_event)
        try:
            event_id = int(created["id"])
            event_uuid = UUID(str(created.get("uuid") or event.uuid))
        except (KeyError, TypeError, ValueError) as exc:
            raise MispClientError("invalid_response") from exc
        return event_id, event_uuid

    async def add_attribute(self, event_id: int, attribute: MispAttribute) -> int:
        """Add one `ip-src` attribute to an existing event."""
        response = await self._request(
            "POST", f"attributes/add/{event_id}", payload={"Attribute": attribute.payload()}
        )
        box = _object(response)
        raw_attribute = box.get("Attribute", box)
        created = _object(raw_attribute)
        try:
            return int(created["id"])
        except (KeyError, TypeError, ValueError) as exc:
            raise MispClientError("invalid_response") from exc

    async def find_event(self, event_uuid: UUID | str) -> MispExistingEvent | None:
        """Read an event by UUID, used to make retries idempotent."""
        try:
            response = await self._request(
                "GET", f"events/view/{quote(str(event_uuid), safe='')}", not_found_ok=True
            )
        except MispNotFoundError:
            return None
        box = _object(response)
        raw_event = box.get("Event", box)
        event = _object(raw_event)
        try:
            identifier = UUID(str(event["uuid"]))
        except (KeyError, TypeError, ValueError) as exc:
            raise MispClientError("invalid_response") from exc
        raw_attributes = box.get("Attribute", event.get("Attribute", []))
        values: set[str] = set()
        to_ids_values: set[str] = set()
        if isinstance(raw_attributes, list):
            for item in raw_attributes:
                if not isinstance(item, dict) or not isinstance(item.get("value"), str):
                    continue
                value = item["value"]
                values.add(value)
                if item.get("to_ids") in (True, 1, "1", "true"):
                    to_ids_values.add(value)
        raw_tags = box.get("Tag", event.get("Tag", []))
        tags: set[str] = set()
        if isinstance(raw_tags, list):
            for item in raw_tags:
                if isinstance(item, dict) and isinstance(item.get("name"), str):
                    tags.add(item["name"])
        distribution = event.get("distribution")
        return MispExistingEvent(
            id=int(event["id"]) if "id" in event else None,
            uuid=identifier,
            distribution=str(distribution) if distribution is not None else "",
            attribute_values=frozenset(values),
            to_ids_values=frozenset(to_ids_values),
            tags=frozenset(tags),
            published=bool(event.get("published", False)),
        )

    async def find_ip_attributes(
        self, values: Sequence[str]
    ) -> dict[str, tuple[MispExistingAttribute, ...]]:
        """Find existing exact `ip-src` attributes for candidate addresses.

        The OpenAPI schema types `value` as a string, so requests are issued per
        address rather than sending an undocumented array. MISP may treat value
        search as substring/wildcard matching; the response is locally
        constrained to the exact canonical value and type. A failed or malformed
        response raises, leaving the durable window queued rather than risking a
        duplicate publication.
        """
        matches: dict[str, tuple[MispExistingAttribute, ...]] = {}
        for value in dict.fromkeys(values):
            response = await self._request(
                "POST",
                "attributes/restSearch",
                payload={"value": value, "type": "ip-src", "limit": 1000, "page": 1},
            )
            rows: Any = response
            if isinstance(response, dict):
                outer = response.get("response", response)
                rows = outer.get("Attribute", []) if isinstance(outer, dict) else []
            if not isinstance(rows, list):
                raise MispClientError("invalid_response")
            found: list[MispExistingAttribute] = []
            for row in rows:
                if not isinstance(row, dict):
                    continue
                raw_id = row.get("id")
                row_value = row.get("value")
                kind = row.get("type")
                if raw_id is None or row_value != value or kind != "ip-src":
                    continue
                try:
                    found.append(MispExistingAttribute(id=int(raw_id), value=value, type=kind))
                except (TypeError, ValueError):
                    raise MispClientError("invalid_response") from None
            if found:
                matches[value] = tuple(found)
        return matches

    async def delete_event(self, event_id: int) -> None:
        """Delete one event, used only by the operator smoke test.

        Production publication never deletes another organisation's data. The
        response is checked because a 200 body with `saved=false` is not a
        successful deletion.
        """
        response = await self._request("DELETE", f"events/delete/{event_id}", payload={})
        box = _object(response)
        if box.get("saved") not in (True, 1, "1", "true"):
            raise MispClientError("delete_failed")

    async def search_tag(self, name: str) -> str | None:
        """Return the exact MISP tag id for `name`, or None when it is absent."""
        try:
            response = await self._request(
                "GET", f"tags/search/{quote(name, safe='')}", not_found_ok=True
            )
        except MispNotFoundError:
            return None
        tags = _list(response, key="Tag")
        for item in tags:
            if isinstance(item, dict) and item.get("name") == name:
                value = item.get("id")
                if value is not None:
                    return str(value)
        return None

    async def warninglists_enabled(self) -> int:
        """Count enabled warninglists.

        Zero is not "no matches": MISP returns an empty check for every value when
        no list is enabled, and publishing on that answer would silently remove
        the last false-positive gate. The caller fails closed when this is zero
        and `misp_warninglist_required` is true.
        """
        response = await self._request("GET", "warninglists/index")
        lists = _list(response, key="Warninglists")
        enabled = 0
        for item in lists:
            if isinstance(item, dict) and item.get("enabled") in (True, 1, "1", "true"):
                enabled += 1
        return enabled

    async def check_warninglists(self, values: Sequence[str]) -> dict[str, tuple[str, ...]]:
        """Return warninglist names matched by each value.

        The Automation API may answer with either a mapping keyed by value or an
        empty JSON array when there are no enabled lists; both shapes are
        accepted here and the latter means "no matches", not an error.
        """
        if not values:
            return {}
        response = await self._request("POST", "warninglists/checkValue", payload=list(values))
        if isinstance(response, list):
            return {}
        if not isinstance(response, dict):
            raise MispClientError("invalid_response")
        result: dict[str, tuple[str, ...]] = {}
        for value in values:
            raw_matches = response.get(value)
            if raw_matches is None:
                continue
            if isinstance(raw_matches, dict):
                if "name" in raw_matches:
                    raw_matches = [raw_matches]
                else:
                    raw_matches = raw_matches.get("Warninglist", raw_matches.get("matches", []))
            if not isinstance(raw_matches, list):
                continue
            names: list[str] = []
            for match in raw_matches:
                if isinstance(match, str):
                    names.append(match)
                elif isinstance(match, dict):
                    name = match.get("name")
                    if isinstance(name, str) and name:
                        names.append(name)
            if names:
                result[value] = tuple(dict.fromkeys(names))
        return result

    async def add_sighting(self, values: Sequence[str]) -> int:
        """Record sightings for values already confirmed as exact `ip-src` hits."""
        unique = list(dict.fromkeys(values))
        if not unique:
            return 0
        response = await self._request(
            "POST",
            "sightings/add",
            payload={"values": unique, "filters": {"type": "ip-src"}},
        )
        if isinstance(response, list):
            return len(response)
        if not isinstance(response, dict):
            raise MispClientError("invalid_response")
        sightings = response.get("Sighting", response)
        if isinstance(sightings, list):
            return len(sightings)
        if isinstance(sightings, dict):
            raw_id = sightings.get("id")
            if raw_id is not None:
                try:
                    return int(raw_id)
                except (TypeError, ValueError) as exc:
                    raise MispClientError("invalid_response") from exc
            return 1 if sightings else 0
        return 0

    async def publish_event(self, event_id: int) -> None:
        """Publish one event. The caller has already decided this is allowed."""
        await self._request("POST", f"events/publish/{event_id}", payload={})

    async def add_event_tag(self, event_id: int, tag_id: str) -> None:
        """Attach a tag without creating a local tag copy."""
        await self._request(
            "POST",
            f"events/addTag/{event_id}/{quote(str(tag_id), safe='')}/local:false",
            payload={},
        )


__all__ = [
    "MispAuthError",
    "MispClient",
    "MispClientError",
    "MispNotFoundError",
]
