#!/usr/bin/env python3
"""Live smoke test for the OpenCTI integration against a real instance.

The unit tests replay `httpx.MockTransport`, so they prove the client's logic but
not that a specific OpenCTI release accepts these GraphQL documents. This tool
runs the real :class:`OpenCTIClient` against a live platform and then asks the
platform itself what it stored, instead of trusting the client's return value:

* a cold lookup answers `not_found` (or `ok` when the address is already known);
* the `missing` pass creates exactly one STIX indicator with the requested
  confidence and the `occ-smoke` label;
* a second alert with a cold cache merges into that indicator (`existing`) and
  does not add a duplicate;
* an `always` pass updates the same indicator in place (`updated`), so its id is
  stable and `confidence` moves;
* two concurrent alerts still leave exactly one indicator.

The indicator is deleted again unless `--keep` is passed, so repeated runs do
not accumulate intelligence. The cache lives in the Redis database named by
`OCC_TEST_REDIS_URL` (use a disposable one); only the two keys of this address
are removed, never the database.

Usage:
    export OCC_OPENCTI_URL=https://opencti.example
    export OCC_OPENCTI_TOKEN=...            # never passed on the command line
    export OCC_TEST_REDIS_URL=redis://localhost:6379/15
    python tools/opencti_smoke.py --address <globally-routable-address>

The address must be globally routable: the client refuses private, loopback and
documentation ranges for a real alert, and this tool exercises that same code
path. Exit codes: 0 pass, 1 assertion failed, 2 usage error, 3 unreachable.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final
from urllib.parse import urlsplit

import httpx
from redis.exceptions import RedisError

from opencanary_correlator.enrichment.geo import public_address
from opencanary_correlator.enrichment.opencti import (
    CreateMode,
    OpenCTIClient,
    OpenCTICreateResult,
    stix_pattern,
)
from opencanary_correlator.storage import keys
from opencanary_correlator.storage.redis_store import RedisStore

PROVIDER: Final[str] = "opencti"
SMOKE_LABEL: Final[str] = "occ-smoke"

EXIT_OK: Final[int] = 0
EXIT_FAILED: Final[int] = 1
EXIT_USAGE: Final[int] = 2
EXIT_UNREACHABLE: Final[int] = 3

#: Reads the connection with the same shape the client queries, plus nothing
#: else: a smoke test that silently accepted a different indicator list would
#: not prove much.
INDICATORS_QUERY: Final[str] = """
query SmokeIndicatorsByPattern($filters: FilterGroup) {
  indicators(filters: $filters, first: 50) {
    edges {
      node {
        id
        pattern
        confidence
        created_at
        valid_from
        objectLabel {
          value
        }
      }
    }
  }
}
""".strip()

DELETE_INDICATOR_MUTATION: Final[str] = """
mutation SmokeDeleteIndicator($id: ID!) {
  indicatorDelete(id: $id)
}
""".strip()


class SmokeError(Exception):
    """The smoke run cannot continue or an assertion about OpenCTI failed."""


@dataclass(frozen=True, slots=True)
class Config:
    """Validated inputs of one run, with the token kept out of the summary."""

    url: str
    token: str
    redis_url: str
    address: str
    confidence: int
    timeout: float
    verify_tls: bool
    keep: bool


@dataclass(slots=True)
class Step:
    """One reported phase of the run."""

    name: str
    status: str
    detail: str = ""


@dataclass(slots=True)
class Report:
    """Collected steps, printed as the JSON summary at the end."""

    steps: list[Step] = field(default_factory=list)

    def add(self, name: str, status: str, detail: str = "") -> None:
        """Record one step and echo it to stderr for a human reading along."""
        self.steps.append(Step(name, status, detail))
        print(f"[{status}] {name}: {detail}", file=sys.stderr)

    @property
    def failed(self) -> bool:
        """True when any step failed; warnings do not fail the run."""
        return any(step.status == "failed" for step in self.steps)


class GraphQL:
    """The two direct calls the assertions need: count and delete.

    These deliberately bypass :class:`OpenCTIClient`: the point is to compare
    what the client believes it wrote with what the platform actually holds.
    """

    def __init__(self, *, url: str, token: str, timeout: float, verify_tls: bool) -> None:
        self._endpoint = f"{url.rstrip('/')}/graphql"
        self._token = token
        self._timeout = timeout
        self._client = httpx.AsyncClient(timeout=timeout, verify=verify_tls)

    async def aclose(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()

    async def _post(self, query: str, variables: dict[str, Any]) -> object:
        """POST one document, translating transport and HTTP faults."""
        try:
            async with asyncio.timeout(self._timeout):
                response = await self._client.post(
                    self._endpoint,
                    json={"query": query, "variables": variables},
                    headers={"Authorization": f"Bearer {self._token}"},
                )
        except (httpx.HTTPError, TimeoutError) as exc:
            raise SmokeError(f"cannot reach OpenCTI: {type(exc).__name__}") from exc
        if response.status_code in (401, 403):
            raise SmokeError("OpenCTI rejected the token (HTTP 401/403)")
        if response.status_code != 200:
            raise SmokeError(f"OpenCTI answered HTTP {response.status_code}")
        try:
            return response.json()
        except ValueError as exc:
            raise SmokeError("OpenCTI answered with a non-JSON body") from exc

    async def count(self, pattern: str) -> list[dict[str, Any]]:
        """Return every indicator that matches `pattern` exactly."""
        payload = await self._post(
            INDICATORS_QUERY,
            {
                "filters": {
                    "mode": "and",
                    "filterGroups": [],
                    "filters": [{"key": "pattern", "values": [pattern], "operator": "eq"}],
                }
            },
        )
        return _nodes(payload)

    async def delete(self, indicator_id: str) -> None:
        """Delete one indicator by id."""
        payload = await self._post(DELETE_INDICATOR_MUTATION, {"id": indicator_id})
        data = _envelope(payload)
        # `indicatorDelete` returns the deleted id; a null answer means the
        # platform did not delete anything, which must not be reported as done.
        if not data.get("indicatorDelete"):
            raise SmokeError("OpenCTI did not delete the indicator")


def _envelope(payload: object) -> dict[str, Any]:
    """Validate the GraphQL envelope and return its `data` object."""
    if not isinstance(payload, dict):
        raise SmokeError("GraphQL response is not a JSON object")
    errors = payload.get("errors")
    if errors:
        raise SmokeError(f"GraphQL returned an error: {_error_text(errors)}")
    data = payload.get("data")
    if not isinstance(data, dict):
        raise SmokeError("GraphQL response has no data object")
    return data


def _error_text(errors: object) -> str:
    """Return the first GraphQL error message, bounded for a terminal."""
    if isinstance(errors, list) and errors:
        head = errors[0]
        if isinstance(head, dict):
            message = head.get("message")
            if isinstance(message, str):
                return message[:300]
    return "unknown error"


def _nodes(payload: object) -> list[dict[str, Any]]:
    """Extract the indicator nodes from an `indicators` connection."""
    data = _envelope(payload)
    connection = data.get("indicators")
    if not isinstance(connection, dict):
        raise SmokeError("GraphQL response has no indicators connection")
    edges = connection.get("edges")
    if not isinstance(edges, list):
        raise SmokeError("GraphQL response has no indicators edges")
    nodes: list[dict[str, Any]] = []
    for edge in edges:
        node = edge.get("node") if isinstance(edge, dict) else None
        if isinstance(node, dict):
            nodes.append(node)
    return nodes


def check(condition: bool, message: str) -> None:
    """Raise :class:`SmokeError` when an assertion about OpenCTI does not hold."""
    if not condition:
        raise SmokeError(message)


def has_label(labels: object, value: str) -> bool:
    """True when `labels` is an `objectLabel` connection carrying `value`."""
    if not isinstance(labels, list):
        return False
    return any(isinstance(entry, dict) and entry.get("value") == value for entry in labels)


def _token_from_file(path: str | None) -> str:
    """Read the token from a file or the environment, never from argv.

    A token in a command line is visible in the process list and lands in shell
    history, so the only accepted inputs are a file or `OCC_OPENCTI_TOKEN`.
    """
    if path is not None:
        try:
            token = Path(path).read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise SmokeError(f"cannot read the token file: {exc.strerror or exc}") from exc
        if not token:
            raise SmokeError("the token file is empty")
        return token
    token = os.environ.get("OCC_OPENCTI_TOKEN", "").strip()
    if not token:
        raise SmokeError("set OCC_OPENCTI_TOKEN or pass --token-file")
    return token


def _origin(url: str) -> str:
    """Render a URL without credentials, for the summary."""
    parts = urlsplit(url)
    if not parts.scheme:
        return url
    host = parts.hostname or ""
    try:
        port = parts.port
    except ValueError:
        port = None
    return f"{parts.scheme}://{host}:{port}" if port else f"{parts.scheme}://{host}"


def build_parser() -> argparse.ArgumentParser:
    """Return the argument parser."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--address",
        required=True,
        help="globally routable address to test with (the client rejects reserved ranges)",
    )
    parser.add_argument("--url", help="OpenCTI base URL; defaults to OCC_OPENCTI_URL")
    parser.add_argument(
        "--token-file",
        help="file holding the API token; defaults to OCC_OPENCTI_TOKEN",
    )
    parser.add_argument(
        "--redis-url",
        help="disposable Redis URL; defaults to OCC_TEST_REDIS_URL or OCC_REDIS_URL",
    )
    parser.add_argument("--confidence", type=int, default=42, help="initial confidence, 0..99")
    parser.add_argument("--timeout", type=float, default=15.0, help="seconds per GraphQL request")
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="skip TLS verification; only for a loopback lab instance",
    )
    parser.add_argument(
        "--keep",
        action="store_true",
        help="keep the created indicator instead of deleting it at the end",
    )
    return parser


def load_config(args: argparse.Namespace) -> Config:
    """Validate the command line into a :class:`Config`."""
    url = (args.url or os.environ.get("OCC_OPENCTI_URL", "")).strip()
    if not url:
        raise SmokeError("set OCC_OPENCTI_URL or pass --url")
    redis_url = (
        args.redis_url
        or os.environ.get("OCC_TEST_REDIS_URL")
        or os.environ.get("OCC_REDIS_URL")
        or ""
    ).strip()
    if not redis_url:
        raise SmokeError("set OCC_TEST_REDIS_URL or pass --redis-url")
    confidence = int(args.confidence)
    if not 0 <= confidence <= 99:
        raise SmokeError("--confidence must be between 0 and 99")
    timeout = float(args.timeout)
    if timeout <= 0:
        raise SmokeError("--timeout must be positive")
    address = public_address(str(args.address))
    if address is None:
        raise SmokeError(
            "the address must be globally routable; private, loopback and documentation "
            "ranges are refused by the same check a real alert goes through"
        )
    return Config(
        url=url,
        token=_token_from_file(args.token_file),
        redis_url=redis_url,
        address=str(address),
        confidence=confidence,
        timeout=timeout,
        verify_tls=not bool(args.insecure),
        keep=bool(args.keep),
    )


def make_client(config: Config, store: RedisStore, mode: CreateMode) -> OpenCTIClient:
    """Build a client for one phase; each phase starts with a cold cache."""
    return OpenCTIClient(
        url=config.url,
        token=config.token,
        store=store,
        create_mode=mode,
        timeout=config.timeout,
        lookup_timeout=config.timeout,
        verify_tls=config.verify_tls,
    )


async def cold_cache(store: RedisStore, address: str) -> None:
    """Forget everything cached for `address`, so the next call hits OpenCTI.

    The singleflight lease is removed as well: a lease left behind by an
    interrupted run would otherwise make this run wait for its expiry.
    """
    await store.delete(
        keys.enrichment_cache_key(PROVIDER, address),
        keys.enrichment_lock_key(PROVIDER, address),
    )


def _expect(result: OpenCTICreateResult, outcome: str, step: str) -> None:
    """Assert the outcome of one create/update pass, with the reason on failure."""
    reason = f" ({result.reason})" if result.reason else ""
    check(
        result.outcome == outcome,
        f"{step}: expected {outcome}, got {result.outcome}{reason} (status {result.status})",
    )


def _indicator_id(result: OpenCTICreateResult) -> str:
    """Return the indicator id a pass reported, or fail with a clear message."""
    check(result.indicator is not None, "the pass returned no indicator")
    indicator = result.indicator
    if indicator is None:  # pragma: no cover - check() already raised
        raise SmokeError("the pass returned no indicator")
    check(bool(indicator.id), "the indicator has no id, so it cannot be updated in place")
    return indicator.id


def summarise(config: Config, report: Report, *, indicator_id: str, count: int) -> None:
    """Print the machine-readable summary; never includes the token."""
    print(
        json.dumps(
            {
                "ok": not report.failed,
                "opencti": _origin(config.url),
                "redis": _origin(config.redis_url),
                "address": config.address,
                "indicator_id": indicator_id,
                "indicator_count": count,
                "steps": [
                    {"name": step.name, "status": step.status, "detail": step.detail}
                    for step in report.steps
                ],
            },
            indent=2,
        )
    )


async def run(config: Config) -> int:
    """Execute every phase and return the process exit code."""
    report = Report()
    store = RedisStore.from_url(config.redis_url)
    graphql = GraphQL(
        url=config.url, token=config.token, timeout=config.timeout, verify_tls=config.verify_tls
    )
    clients: list[OpenCTIClient] = []
    indicator_id = ""
    final_count = 0
    try:
        if not await store.ping():
            report.add("redis", "failed", f"Redis is not reachable: {_origin(config.redis_url)}")
            return EXIT_UNREACHABLE

        address = public_address(config.address)
        if address is None:  # pragma: no cover - load_config validated it
            raise SmokeError("the address is no longer globally routable")
        pattern = stix_pattern(address)

        try:
            baseline = await graphql.count(pattern)
        except SmokeError as exc:
            report.add("baseline", "failed", str(exc))
            return EXIT_UNREACHABLE
        if len(baseline) > 1:
            print(
                f"error: {config.address} already has {len(baseline)} indicators in OpenCTI; "
                "use another address so the duplicate check is meaningful",
                file=sys.stderr,
            )
            return EXIT_FAILED
        report.add("baseline", "ok", f"{len(baseline)} existing indicator(s)")

        phase = "lookup"
        try:
            await cold_cache(store, config.address)
            lookup, status = await make_client_of(config, store, clients, "off").lookup(
                config.address
            )
            check(
                status in ("ok", "not_found"),
                f"the lookup answered {status}, so OpenCTI is unreachable or refused the token",
            )
            check(
                (lookup is not None) == (len(baseline) == 1),
                "the lookup and the direct query disagree about whether the indicator exists",
            )
            report.add("lookup", "ok", f"status={status}")
        except SmokeError as exc:
            report.add(phase, "failed", str(exc))
            if status_is_unreachable(str(exc)):
                return EXIT_UNREACHABLE
            raise

        phase = "create"
        try:
            creator = make_client_of(config, store, clients, "missing")
            await cold_cache(store, config.address)
            created = await creator.create_or_update(
                config.address, confidence=config.confidence, labels=(SMOKE_LABEL,)
            )
            _expect(created, "existing" if baseline else "created", "create")
            check(created.status == "ok", f"create reported status {created.status}")
            indicator_id = _indicator_id(created)
            nodes = await graphql.count(pattern)
            final_count = len(nodes)
            check(final_count == 1, f"OpenCTI holds {final_count} indicators, expected 1")
            check(nodes[0].get("pattern") == pattern, "the stored pattern differs from the request")
            check(
                nodes[0].get("id") == indicator_id,
                "the direct query returned a different indicator than the client reported",
            )
            check(
                int(nodes[0].get("confidence") or -1) == config.confidence,
                f"stored confidence is {nodes[0].get('confidence')!r}, "
                f"expected {config.confidence}",
            )
            check(
                has_label(nodes[0].get("objectLabel"), SMOKE_LABEL),
                f"the {SMOKE_LABEL} label is not attached to the indicator",
            )
            report.add(phase, "ok", f"{created.outcome} {indicator_id}")
        except SmokeError as exc:
            report.add(phase, "failed", str(exc))
            raise

        phase = "repeat_alert"
        try:
            await cold_cache(store, config.address)
            repeated = await creator.create_or_update(
                config.address, confidence=config.confidence, labels=(SMOKE_LABEL,)
            )
            _expect(repeated, "existing", "repeat alert")
            check(
                _indicator_id(repeated) == indicator_id,
                "the repeat alert resolved to a different indicator",
            )
            nodes = await graphql.count(pattern)
            final_count = len(nodes)
            check(
                final_count == 1,
                f"the repeat alert left {final_count} indicators, expected 1",
            )
            report.add(phase, "ok", "merged into the same indicator")
        except SmokeError as exc:
            report.add(phase, "failed", str(exc))
            raise

        phase = "update"
        try:
            updated_confidence = config.confidence + 35
            if updated_confidence > 100:
                updated_confidence = 99
            updater = make_client_of(config, store, clients, "always")
            await cold_cache(store, config.address)
            updated = await updater.create_or_update(
                config.address, confidence=updated_confidence, labels=(SMOKE_LABEL,)
            )
            _expect(updated, "updated", "update")
            check(
                _indicator_id(updated) == indicator_id,
                "the update changed the indicator id instead of patching in place",
            )
            nodes = await graphql.count(pattern)
            final_count = len(nodes)
            check(final_count == 1, f"the update left {final_count} indicators, expected 1")
            check(
                nodes[0].get("id") == indicator_id,
                "the stored indicator id changed after the update",
            )
            check(
                int(nodes[0].get("confidence") or -1) == updated_confidence,
                f"stored confidence is {nodes[0].get('confidence')!r}, "
                f"expected {updated_confidence}",
            )
            report.add(phase, "ok", f"confidence {config.confidence} -> {updated_confidence}")
        except SmokeError as exc:
            report.add(phase, "failed", str(exc))
            raise

        phase = "concurrent_alerts"
        try:
            race_confidence = updated_confidence + 1 if updated_confidence < 100 else 99
            first = make_client_of(config, store, clients, "always")
            second = make_client_of(config, store, clients, "always")
            await cold_cache(store, config.address)
            results = await asyncio.gather(
                first.create_or_update(
                    config.address, confidence=race_confidence, labels=(SMOKE_LABEL,)
                ),
                second.create_or_update(
                    config.address, confidence=race_confidence, labels=(SMOKE_LABEL,)
                ),
            )
            for result in results:
                check(
                    result.outcome in ("created", "updated", "existing"),
                    f"a concurrent alert ended as {result.outcome} ({result.reason})",
                )
                check(result.status == "ok", f"a concurrent alert reported {result.status}")
                check(
                    _indicator_id(result) == indicator_id,
                    "a concurrent alert targeted a different indicator",
                )
            nodes = await graphql.count(pattern)
            final_count = len(nodes)
            check(
                final_count == 1,
                f"two concurrent alerts produced {final_count} indicators, expected 1",
            )
            check(
                int(nodes[0].get("confidence") or -1) == race_confidence,
                f"stored confidence is {nodes[0].get('confidence')!r}, expected {race_confidence}",
            )
            report.add(phase, "ok", "one indicator after two concurrent alerts")
        except SmokeError as exc:
            report.add(phase, "failed", str(exc))
            raise

        phase = "cleanup"
        if config.keep:
            report.add(phase, "warn", f"keeping {indicator_id} (--keep)")
        else:
            try:
                await graphql.delete(indicator_id)
                await cold_cache(store, config.address)
                remaining = await graphql.count(pattern)
                final_count = len(remaining)
                check(final_count == 0, f"{final_count} indicator(s) remain after the delete")
                report.add(phase, "ok", f"deleted {indicator_id}")
            except SmokeError as exc:
                report.add(phase, "warn", f"could not delete {indicator_id}: {exc}")
        return EXIT_OK if not report.failed else EXIT_FAILED
    except RedisError as exc:
        report.add("redis", "failed", f"Redis error: {type(exc).__name__}")
        return EXIT_UNREACHABLE
    except SmokeError:
        if not report.failed:
            report.add("smoke", "failed", "the run stopped before its first assertion")
        return EXIT_FAILED
    finally:
        summarise(config, report, indicator_id=indicator_id, count=final_count)
        for client in clients:
            await client.aclose()
        await graphql.aclose()
        await store.aclose()


def status_is_unreachable(message: str) -> bool:
    """True when a lookup failure means OpenCTI was not usable at all."""
    return any(
        marker in message
        for marker in ("unreachable", "refused", "cannot reach", "HTTP 401", "HTTP 403")
    )


def make_client_of(
    config: Config,
    store: RedisStore,
    clients: list[OpenCTIClient],
    mode: CreateMode,
) -> OpenCTIClient:
    """Build a client and register it for closing."""
    client = make_client(config, store, mode)
    clients.append(client)
    return client


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
