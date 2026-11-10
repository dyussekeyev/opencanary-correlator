"""Safety tests for the MISP live smoke-test tool."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import unquote

import httpx
import pytest
from tools.misp_smoke import Config, SmokeError, build_parser, load_config, run

from opencanary_correlator.connectors.publishers.misp import MispClient

ADDRESS = "198.51.100.7"


def _config(*, execute: bool, allow_warninglisted: bool = False) -> Config:
    return Config(
        url="https://misp.test",
        api_key="smoke-secret",
        address=ADDRESS,
        tlp="amber",
        pap="amber",
        confidence_tag='misp:confidence-level="rarely-confident"',
        tags=("honeypot",),
        timeout=5,
        verify_tls=True,
        execute=execute,
        keep=False,
        allow_warninglisted=allow_warninglisted,
    )


def _client(handler: Any) -> tuple[MispClient, httpx.AsyncClient]:
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return MispClient(url="https://misp.test", api_key="smoke-secret", client=http), http


def test_smoke_config_does_not_expose_the_key() -> None:
    config = _config(execute=False)
    assert "smoke-secret" not in repr(config)


async def test_dry_run_checks_tags_and_warninglists_without_writing() -> None:
    calls: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path))
        if request.url.path == "/warninglists/index":
            return httpx.Response(
                200, json={"Warninglists": [{"id": "1", "enabled": True}]}, request=request
            )
        if request.url.path == "/warninglists/checkValue":
            return httpx.Response(200, json={}, request=request)
        name = unquote(request.url.path.rsplit("/", 1)[-1])
        return httpx.Response(200, json={"Tag": [{"id": "1", "name": name}]}, request=request)

    client, http = _client(handler)
    assert await run(_config(execute=False), client=client) == 0
    await http.aclose()

    assert not any(method == "POST" and path.startswith("/events/") for method, path in calls)
    assert any(path == "/warninglists/checkValue" for _method, path in calls)


async def test_execute_creates_verifies_and_deletes_one_draft() -> None:
    state: dict[str, Any] = {"event_uuid": "", "deleted": False, "tag_names": []}
    calls: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path))
        if request.url.path == "/warninglists/index":
            return httpx.Response(
                200, json={"Warninglists": [{"id": "1", "enabled": True}]}, request=request
            )
        if request.url.path == "/warninglists/checkValue":
            return httpx.Response(200, json={}, request=request)
        if request.method == "GET" and request.url.path.startswith("/events/view/"):
            if state["deleted"]:
                return httpx.Response(404, request=request)
            return httpx.Response(
                200,
                json={
                    "Event": {
                        "id": "900",
                        "uuid": state["event_uuid"],
                        "distribution": "0",
                        "published": False,
                    },
                    "Attribute": [{"value": ADDRESS, "to_ids": False}],
                    "Tag": [{"name": name} for name in state["tag_names"]],
                },
                request=request,
            )
        if request.url.path == "/events/add":
            body = json.loads(request.read())
            state["event_uuid"] = body["Event"]["uuid"]
            state["tag_names"] = [
                name
                for name in (
                    "tlp:amber",
                    "pap:amber",
                    'misp:confidence-level="rarely-confident"',
                    "honeypot",
                )
            ]
            return httpx.Response(
                200,
                json={"Event": {"id": "900", "uuid": state["event_uuid"]}},
                request=request,
            )
        if request.url.path.startswith("/events/addTag/"):
            return httpx.Response(200, json={}, request=request)
        if request.url.path.startswith("/attributes/add/"):
            return httpx.Response(200, json={"Attribute": {"id": "901"}}, request=request)
        if request.method == "DELETE" and request.url.path == "/events/delete/900":
            state["deleted"] = True
            return httpx.Response(200, json={"saved": True}, request=request)
        name = unquote(request.url.path.rsplit("/", 1)[-1])
        return httpx.Response(200, json={"Tag": [{"id": "1", "name": name}]}, request=request)

    client, http = _client(handler)
    assert await run(_config(execute=True), client=client) == 0
    await http.aclose()

    assert ("POST", "/events/add") in calls
    assert ("DELETE", "/events/delete/900") in calls
    assert ("GET", f"/events/view/{state['event_uuid']}") in calls


async def test_execute_refuses_a_warninglist_hit_before_writing() -> None:
    calls: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path))
        if request.url.path == "/warninglists/index":
            return httpx.Response(
                200, json={"Warninglists": [{"id": "1", "enabled": True}]}, request=request
            )
        if request.url.path == "/warninglists/checkValue":
            return httpx.Response(200, json={ADDRESS: [{"name": "RFC 5737"}]}, request=request)
        name = unquote(request.url.path.rsplit("/", 1)[-1])
        return httpx.Response(200, json={"Tag": [{"id": "1", "name": name}]}, request=request)

    client, http = _client(handler)
    assert await run(_config(execute=True), client=client) == 1
    await http.aclose()

    assert ("POST", "/events/add") not in calls


async def test_failure_after_create_still_deletes_the_draft() -> None:
    state: dict[str, Any] = {"deleted": False}
    calls: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path))
        if request.url.path == "/warninglists/index":
            return httpx.Response(
                200, json={"Warninglists": [{"id": "1", "enabled": True}]}, request=request
            )
        if request.url.path == "/warninglists/checkValue":
            return httpx.Response(200, json={}, request=request)
        if request.url.path == "/events/add":
            body = json.loads(request.read())
            return httpx.Response(
                200, json={"Event": {"id": "900", "uuid": body["Event"]["uuid"]}}, request=request
            )
        if request.url.path.startswith("/attributes/add/"):
            return httpx.Response(500, json={"errors": "broken"}, request=request)
        if request.method == "DELETE" and request.url.path == "/events/delete/900":
            state["deleted"] = True
            return httpx.Response(200, json={"saved": True}, request=request)
        name = unquote(request.url.path.rsplit("/", 1)[-1])
        return httpx.Response(200, json={"Tag": [{"id": "1", "name": name}]}, request=request)

    client, http = _client(handler)
    assert await run(_config(execute=True), client=client) == 1
    await http.aclose()

    assert state["deleted"] is True
    assert ("DELETE", "/events/delete/900") in calls


@pytest.mark.parametrize("flag", ["--keep", "--allow-warninglisted"])
def test_unsafe_write_flags_require_execute(flag: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OCC_MISP_API_KEY", "smoke-secret")
    args = build_parser().parse_args(["--url", "https://misp.test", "--address", ADDRESS, flag])
    with pytest.raises(SmokeError, match="requires --execute"):
        load_config(args)
