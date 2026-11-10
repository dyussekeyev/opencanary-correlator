#!/usr/bin/env python3
"""Safe live draft smoke test for the MISP publisher's prerequisites.

The unit tests use ``httpx.MockTransport``; this tool exercises the real MISP
Automation API only when the operator explicitly asks for a write. It is
deliberately conservative:

* the default mode is read-only and checks the API key, exact TLP/PAP/confidence
  and honeypot tags, enabled warninglists and the warninglist answer for the test
  address;
* ``--execute`` creates exactly one unpublished ``distribution=0`` event with
  one documentation-range ``ip-src``, ``to_ids=false`` and no real observation;
* the event is read back and checked, then deleted; a failure after creation
  still attempts deletion, and the event id is printed if cleanup cannot finish;
* no publish endpoint is ever called and no MISP object is modified except the
  temporary smoke-test event.

The API key comes from a file or ``OCC_MISP_API_KEY``, never from argv. The URL
comes from ``--url`` or ``OCC_MISP_URL``. A documentation address may itself be
listed in a warninglist; the write mode refuses that by default. Use
``--allow-warninglisted`` only after confirming why the test address matched.

Usage:
    export OCC_MISP_URL=https://misp.example
    export OCC_MISP_API_KEY=...          # or use --token-file
    python tools/misp_smoke.py --address 198.51.100.7
    python tools/misp_smoke.py --address 198.51.100.7 --execute

Exit codes: 0 pass or dry-run preflight, 1 assertion/API failure, 2 usage error,
3 unreachable/authentication failure.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import os
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Final
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from opencanary_correlator.config_validation import (
    LOOPBACK_HOSTS,
    MISP_PAP_LEVELS,
    MISP_TLP_LEVELS,
    normalise_misp_url,
    require_misp_url,
    validate_misp_handling,
    validate_misp_tags,
)
from opencanary_correlator.connectors.publishers.misp import (
    MispAttribute,
    MispAuthError,
    MispClient,
    MispClientError,
    MispEvent,
    MispEventBuilder,
    MispObservation,
    MispWindow,
)

EXIT_OK: Final[int] = 0
EXIT_FAILED: Final[int] = 1
EXIT_USAGE: Final[int] = 2
EXIT_UNREACHABLE: Final[int] = 3

DEFAULT_ADDRESS: Final[str] = "198.51.100.7"
DEFAULT_CONFIDENCE_TAG: Final[str] = 'misp:confidence-level="rarely-confident"'
DOCUMENTATION_NETWORKS: Final[tuple[ipaddress.IPv4Network, ...]] = (
    ipaddress.IPv4Network("192.0.2.0/24"),
    ipaddress.IPv4Network("198.51.100.0/24"),
    ipaddress.IPv4Network("203.0.113.0/24"),
)


class SmokeError(Exception):
    """The smoke run cannot continue or an assertion failed."""


@dataclass(frozen=True, slots=True)
class Config:
    """Validated inputs, with the API key kept out of the summary."""

    url: str
    api_key: str = field(repr=False)
    address: str
    tlp: str
    pap: str
    confidence_tag: str
    tags: tuple[str, ...]
    timeout: float
    verify_tls: bool
    execute: bool
    keep: bool
    allow_warninglisted: bool


@dataclass(slots=True)
class Step:
    """One reported phase."""

    name: str
    status: str
    detail: str = ""


@dataclass(slots=True)
class Report:
    """Collected steps, printed as the final JSON summary."""

    steps: list[Step] = field(default_factory=list)

    def add(self, name: str, status: str, detail: str = "") -> None:
        """Record one step and echo it to stderr."""
        self.steps.append(Step(name, status, detail))
        print(f"[{status}] {name}: {detail}", file=sys.stderr)

    @property
    def failed(self) -> bool:
        """True when any step failed; warnings do not fail the run."""
        return any(step.status == "failed" for step in self.steps)


def _origin(url: str) -> str:
    """Render a URL without credentials or query data for the summary."""
    parts = urlsplit(url)
    if not parts.scheme:
        return url
    host = parts.hostname or ""
    try:
        port = parts.port
    except ValueError:
        port = None
    return f"{parts.scheme}://{host}:{port}" if port else f"{parts.scheme}://{host}"


def _token_from_file(path: str | None) -> str:
    """Read the API key from a file or the environment, never from argv."""
    if path is not None:
        try:
            token = Path(path).read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise SmokeError(f"cannot read the token file: {exc.strerror or exc}") from exc
        if not token:
            raise SmokeError("the token file is empty")
        return token
    token = os.environ.get("OCC_MISP_API_KEY", "").strip()
    if not token:
        raise SmokeError("set OCC_MISP_API_KEY or pass --token-file")
    return token


def _test_address(raw: str) -> str:
    """Accept a documentation or globally routable address, never private space."""
    try:
        address = ipaddress.ip_address(raw.strip())
    except ValueError as exc:
        raise SmokeError("--address must be an IP address") from exc
    if (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
    ):
        raise SmokeError("--address must be documentation or globally routable, not private space")
    if address.is_global:
        return str(address)
    if isinstance(address, ipaddress.IPv4Address) and any(
        address in network for network in DOCUMENTATION_NETWORKS
    ):
        return str(address)
    raise SmokeError("--address must be documentation or globally routable")


def _split_tags(raw: str) -> list[str]:
    """Parse the comma-separated tag setting without accepting blank entries."""
    return [part.strip() for part in raw.split(",") if part.strip()]


def build_parser() -> argparse.ArgumentParser:
    """Return the command-line parser."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--url",
        help="MISP base URL; defaults to OCC_MISP_URL",
    )
    parser.add_argument(
        "--token-file",
        help="file holding the API key; defaults to OCC_MISP_API_KEY",
    )
    parser.add_argument(
        "--address",
        default=DEFAULT_ADDRESS,
        help="documentation/global test address (default: %(default)s)",
    )
    parser.add_argument("--tlp", default=os.environ.get("OCC_MISP_TLP", "amber"))
    parser.add_argument("--pap", default=os.environ.get("OCC_MISP_PAP", "amber"))
    parser.add_argument(
        "--confidence-tag",
        default=os.environ.get("OCC_MISP_CONFIDENCE_TAG", DEFAULT_CONFIDENCE_TAG),
    )
    parser.add_argument(
        "--tag",
        action="append",
        dest="tags",
        help="free-form event tag; repeatable (default: OCC_MISP_TAGS or honeypot)",
    )
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="skip TLS verification; only allowed for a loopback lab URL",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="create the single draft; without this flag the run is read-only",
    )
    parser.add_argument(
        "--keep",
        action="store_true",
        help="keep the created draft for inspection instead of deleting it",
    )
    parser.add_argument(
        "--allow-warninglisted",
        action="store_true",
        help="allow --execute when the test address matches an enabled warninglist",
    )
    return parser


def load_config(args: argparse.Namespace) -> Config:
    """Validate command-line and environment input into :class:`Config`."""
    raw_url = (args.url or os.environ.get("OCC_MISP_URL", "")).strip()
    if not raw_url:
        raise SmokeError("set OCC_MISP_URL or pass --url")
    try:
        url = require_misp_url(normalise_misp_url(raw_url))
    except ValueError as exc:
        raise SmokeError(str(exc)) from exc
    if url is None:  # pragma: no cover - raw_url is non-empty
        raise SmokeError("MISP URL is empty")

    timeout = float(args.timeout)
    if timeout <= 0:
        raise SmokeError("--timeout must be positive")
    if args.insecure and urlsplit(url).hostname not in LOOPBACK_HOSTS:
        raise SmokeError("--insecure is only allowed for a loopback MISP URL")
    if args.keep and not args.execute:
        raise SmokeError("--keep requires --execute")
    if args.allow_warninglisted and not args.execute:
        raise SmokeError("--allow-warninglisted requires --execute")

    raw_tags = args.tags
    if raw_tags is None:
        raw_tags = _split_tags(os.environ.get("OCC_MISP_TAGS", "honeypot"))
    try:
        tags = tuple(validate_misp_tags(list(raw_tags)))
        tlp = validate_misp_handling(str(args.tlp), name="misp_tlp", allowed=MISP_TLP_LEVELS)
        pap = validate_misp_handling(str(args.pap), name="misp_pap", allowed=MISP_PAP_LEVELS)
    except ValueError as exc:
        raise SmokeError(str(exc)) from exc
    confidence_tag = str(args.confidence_tag).strip()
    if not confidence_tag:
        raise SmokeError("--confidence-tag must not be empty")

    return Config(
        url=url,
        api_key=_token_from_file(args.token_file),
        address=_test_address(str(args.address)),
        tlp=tlp,
        pap=pap,
        confidence_tag=confidence_tag,
        tags=tags,
        timeout=timeout,
        verify_tls=not bool(args.insecure),
        execute=bool(args.execute),
        keep=bool(args.keep),
        allow_warninglisted=bool(args.allow_warninglisted),
    )


def build_event(config: Config) -> MispEvent:
    """Build one inert draft event with no real observation content."""
    now = datetime.now(UTC).replace(microsecond=0)
    start = now.replace(minute=0, second=0)
    observation = MispObservation(
        ip=config.address,
        first_seen=now,
        last_seen=now,
        count=1,
        services={"ssh.login_attempt": 1},
        ports={22: 1},
    )
    builder = MispEventBuilder(
        # A unique namespace keeps a repeated smoke run from colliding with a
        # previous draft while still producing stable UUIDs within this run.
        namespace=f"occ-smoke:{uuid4().hex}",
        distribution=0,
        tlp=config.tlp,
        pap=config.pap,
        confidence_tag=config.confidence_tag,
        source_tags=config.tags,
        to_ids_types=frozenset(),
        to_ids_min_events=1,
    )
    return builder.build(
        MispWindow(
            start=start,
            end=start + timedelta(hours=1),
            observations=(observation,),
        )
    )


def _check(condition: bool, message: str) -> None:
    """Raise :class:`SmokeError` when an assertion does not hold."""
    if not condition:
        raise SmokeError(message)


def _tag_names(event: MispEvent) -> tuple[str, ...]:
    """Return the exact event tag names the draft must carry."""
    return event.tags


async def _preflight(
    client: MispClient,
    event: MispEvent,
    config: Config,
    report: Report,
) -> dict[str, str]:
    """Resolve every configured tag and verify the warninglist gate."""
    tag_ids: dict[str, str] = {}
    for name in _tag_names(event):
        tag_id = await client.search_tag(name)
        if tag_id is None:
            raise SmokeError(f"required tag is absent: {name}")
        tag_ids[name] = tag_id
    report.add("tags", "ok", f"{len(tag_ids)} configured tag(s) resolved")

    enabled = await client.warninglists_enabled()
    if enabled == 0:
        raise SmokeError("no warninglist is enabled; the publisher would fail closed")
    report.add("warninglists", "ok", f"{enabled} enabled list(s)")

    matches = await client.check_warninglists([config.address])
    if matches:
        names = ", ".join(matches[config.address])
        if not config.allow_warninglisted:
            raise SmokeError(
                f"{config.address} matches a warninglist ({names}); "
                "pass --allow-warninglisted only after reviewing the match"
            )
        report.add("warninglist_match", "warn", f"{config.address}: {names}")
    else:
        report.add("warninglist_match", "ok", f"{config.address} is not warninglisted")
    return tag_ids


async def _create_event(
    client: MispClient,
    event: MispEvent,
    report: Report,
) -> tuple[int, UUID]:
    """Create the empty draft and return its id immediately.

    The caller stores the id before attaching anything, so a later attribute,
    tag or verification failure can still remove the temporary event.
    """
    event_id, event_uuid = await client.add_event(event.model_copy(update={"attributes": ()}))
    report.add("create", "ok", f"event {event_id} created as an unpublished draft")
    return event_id, event_uuid


async def _attach_event(
    client: MispClient,
    event: MispEvent,
    event_id: int,
    tag_ids: dict[str, str],
    report: Report,
) -> None:
    """Attach the single test attribute and every preflight-resolved tag."""
    attribute: MispAttribute = event.attributes[0]
    attribute_id = await client.add_attribute(event_id, attribute)
    report.add("attribute", "ok", f"attribute {attribute_id} added")

    for name, tag_id in tag_ids.items():
        await client.add_event_tag(event_id, tag_id)
        report.add("tag", "ok", f"{name} attached")


async def _verify_event(
    client: MispClient,
    event: MispEvent,
    event_id: int,
    report: Report,
) -> None:
    """Read the temporary event back and assert every safety property."""
    stored = await client.find_event(event.uuid)
    if stored is None:
        raise SmokeError("the created event cannot be read back")
    _check(stored.id == event_id, "the stored event id differs from the create response")
    _check(stored.distribution == "0", f"distribution is {stored.distribution!r}, expected '0'")
    _check(stored.published is False, "the smoke-test event is unexpectedly published")
    attribute: MispAttribute = event.attributes[0]
    _check(attribute.value in stored.attribute_values, "the test attribute is missing")
    _check(
        attribute.value not in stored.to_ids_values,
        "the smoke-test attribute unexpectedly carries to_ids=true",
    )
    missing = set(_tag_names(event)) - stored.tags
    _check(not missing, "missing tags after write: " + ", ".join(sorted(missing)))
    report.add("verify", "ok", "draft, attribute, to_ids=false and tags verified")


def _exit_for_error(exc: MispClientError) -> int:
    """Map a client failure to the documented exit code."""
    if isinstance(exc, MispAuthError) or exc.reason == "transport_error":
        return EXIT_UNREACHABLE
    return EXIT_FAILED


async def run(config: Config, client: MispClient | None = None) -> int:
    """Run preflight, and only with ``--execute`` create and remove one draft."""
    report = Report()
    client = client or MispClient(
        url=config.url,
        api_key=config.api_key,
        verify_tls=config.verify_tls,
        timeout=config.timeout,
    )
    event = build_event(config)
    event_id: int | None = None
    deleted = False
    cleanup_failed = False
    exit_code = EXIT_FAILED
    try:
        report.add(
            "mode",
            "ok",
            "execute: one temporary draft will be created"
            if config.execute
            else "dry-run: no MISP write will be attempted",
        )
        report.add("event_uuid", "ok", str(event.uuid))
        tag_ids = await _preflight(client, event, config, report)
        if not config.execute:
            report.add("write", "skipped", "pass --execute to create the draft")
            exit_code = EXIT_OK
        else:
            event_id, event_uuid = await _create_event(client, event, report)
            _check(event_uuid == event.uuid, "MISP returned a different event UUID")
            await _attach_event(client, event, event_id, tag_ids, report)
            await _verify_event(client, event, event_id, report)
            if config.keep:
                report.add("cleanup", "warn", f"keeping event {event_id} (--keep)")
            else:
                await client.delete_event(event_id)
                deleted = True
                stored = await client.find_event(event.uuid)
                _check(stored is None, "the smoke-test event still exists after deletion")
                report.add("delete", "ok", f"event {event_id} deleted and verified absent")
            exit_code = EXIT_OK if not report.failed else EXIT_FAILED
    except MispClientError as exc:
        report.add("misp", "failed", f"{exc.reason} (status {exc.status_code or 'n/a'})")
        exit_code = _exit_for_error(exc)
    except SmokeError as exc:
        report.add("smoke", "failed", str(exc))
        exit_code = EXIT_FAILED
    finally:
        if event_id is not None and not deleted and not config.keep:
            try:
                await client.delete_event(event_id)
                deleted = True
                report.add("cleanup", "ok", f"event {event_id} deleted after a failed run")
            except MispClientError as exc:
                cleanup_failed = True
                report.add(
                    "cleanup",
                    "failed",
                    f"event {event_id} may remain; delete it manually: {exc.reason}",
                )
        await client.aclose()
        if cleanup_failed:
            exit_code = EXIT_FAILED
        print(
            json.dumps(
                {
                    "ok": not report.failed and not cleanup_failed,
                    "misp": _origin(config.url),
                    "address": config.address,
                    "event_id": event_id,
                    "event_uuid": str(event.uuid),
                    "tags": list(_tag_names(event)),
                    "steps": [
                        {"name": step.name, "status": step.status, "detail": step.detail}
                        for step in report.steps
                    ],
                },
                indent=2,
            )
        )
    return exit_code


def main(argv: list[str] | None = None) -> int:
    """Parse arguments and run the smoke test."""
    args = build_parser().parse_args(argv)
    try:
        config = load_config(args)
    except SmokeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    return asyncio.run(run(config))


if __name__ == "__main__":
    raise SystemExit(main())
