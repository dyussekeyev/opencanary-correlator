"""OpenCTI indicator lookup and creation for attacker addresses.

Lookup only reads. Creation writes a STIX 2.1 indicator, so it is a separate
decision (`create_mode`) with its own gate: `missing` writes only when the
lookup found nothing, and `always` creates or updates the existing indicator.
Before every write the exact pattern is looked up again, which is what keeps the
integration idempotent — the correlator never creates a duplicate just because
two replicas or two alerts raced.

The GraphQL queries target the `FilterGroup` argument of OpenCTI 6.x and ask only
for fields present in both 5.x and 6.x. Nothing is retried: a write is attempted
once, and every failure is audited and reported to the caller instead of raised,
because the alert is already being delivered.
"""

from __future__ import annotations

import asyncio
import ipaddress
import math
from collections.abc import Sequence
from contextlib import AsyncExitStack
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final, Literal, Self, cast

import httpx
from pydantic import BaseModel, ConfigDict, SecretStr, ValidationError, model_validator
from redis.exceptions import RedisError

from opencanary_correlator import metrics
from opencanary_correlator.audit import AuditLogger
from opencanary_correlator.enrichment.geo import public_address
from opencanary_correlator.enrichment.models import OpenCTIIndicator, OpenCTIStatus
from opencanary_correlator.storage import keys
from opencanary_correlator.storage.redis_store import RedisStore

#: Filter by the exact STIX pattern, which is how OpenCTI indexes an address.
INDICATOR_QUERY: Final[str] = """
query IndicatorByPattern($filters: FilterGroup) {
  indicators(filters: $filters, first: 1) {
    edges {
      node {
        id
        pattern
        confidence
        created_at
        valid_from
      }
    }
  }
}
""".strip()

ADD_INDICATOR_MUTATION: Final[str] = """
mutation AddIndicator($input: IndicatorAddInput!) {
  indicatorAdd(input: $input) {
    id
    pattern
    confidence
    created_at
    valid_from
  }
}
""".strip()

#: `indicatorFieldPatch` is the supported way to change an existing indicator's
#: fields; `indicatorEdit` replaces the object and would reset `created_at`.
PATCH_INDICATOR_MUTATION: Final[str] = """
mutation PatchIndicator($id: ID!, $input: [EditInput!]!) {
  indicatorFieldPatch(id: $id, input: $input) {
    id
    pattern
    confidence
    created_at
    valid_from
  }
}
""".strip()

#: Label values are not accepted by `IndicatorAddInput`: OpenCTI 6.x takes
#: `objectLabel` ids, so a configured name is resolved (and created when it does
#: not exist) before the write. Querying by value needs no extra endpoint.
LABEL_QUERY: Final[str] = """
query LabelByValue($filters: FilterGroup) {
  labels(filters: $filters, first: 1) {
    edges {
      node {
        id
        value
      }
    }
  }
}
""".strip()

ADD_LABEL_MUTATION: Final[str] = """
mutation AddLabel($input: LabelAddInput!) {
  labelAdd(input: $input) {
    id
    value
  }
}
""".strip()

#: Fixed description for every created indicator: no honeypot address, node ID
#: or captured log entry, because the indicator describes the attacker only.
INDICATOR_DESCRIPTION: Final[str] = (
    "Attacker address observed by an OpenCanary honeypot correlator."
)

#: Provider name used in metrics and audit records.
PROVIDER: Final[str] = "opencti"

#: `off` never writes, `missing` writes only when nothing was found, and
#: `always` creates or updates. No other value is accepted.
CreateMode = Literal["off", "missing", "always"]
CREATE_MODES: Final[tuple[str, ...]] = ("off", "missing", "always")

#: What one write pass did, or why it did nothing.
CreateOutcome = Literal["created", "updated", "existing", "skipped", "failed"]


@dataclass(frozen=True, slots=True)
class OpenCTICreateResult:
    """Outcome of one `create_or_update` call.

    `status` mirrors the lookup vocabulary, so a caller can tell "the platform
    said the indicator already exists" (`ok`) apart from "the platform refused
    the token" (`unauthorized`) without inspecting a string.
    """

    outcome: CreateOutcome
    indicator: OpenCTIIndicator | None = None
    status: OpenCTIStatus = "ok"
    reason: str = ""


class _CacheEntry(BaseModel):
    """One cached answer; `found: false` is a stored "no indicator".

    The two fields have to agree. A truncated or hand-edited entry that claims
    a hit without an indicator would otherwise put an empty OpenCTI row on every
    alert that follows.
    """

    model_config = ConfigDict(extra="forbid")

    found: bool
    indicator: OpenCTIIndicator | None = None

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if self.found != (self.indicator is not None):
            raise ValueError("cache entry is inconsistent")
        return self


@dataclass(frozen=True, slots=True)
class _Mutation:
    """One write attempt: the returned node, or why it did not happen."""

    node: dict[str, Any] | None = None
    reason: str | None = None
    status: OpenCTIStatus = "ok"


def stix_pattern(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    """Return the STIX 2.1 pattern OpenCTI stores for an address.

    The caller passes an already-parsed address, never the raw event field, so
    the value inside the quotes cannot carry a quote or a bracket of its own.
    """
    kind = "ipv4-addr" if isinstance(address, ipaddress.IPv4Address) else "ipv6-addr"
    return f"[{kind}:value = '{address}']"


def stix_datetime(value: datetime | None = None) -> str:
    """Render an incident time as STIX/ISO 8601 in UTC.

    A naive datetime is read as UTC rather than rejected: the correlator stores
    UTC everywhere, and the alternative is an indicator without `valid_from`.
    """
    moment = value if value is not None else datetime.now(tz=UTC)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def main_observable_type(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    """The `x_opencti_main_observable_type` OpenCTI expects for the pattern."""
    return "IPv4-Addr" if isinstance(address, ipaddress.IPv4Address) else "IPv6-Addr"


class OpenCTIClient:
    """Ask OpenCTI about an address, and optionally write an indicator."""

    name = PROVIDER

    def __init__(
        self,
        *,
        url: str,
        token: SecretStr | str,
        store: RedisStore,
        create_mode: CreateMode = "off",
        cache_ttl: float = 3600.0,
        miss_cache_ttl: float = 300.0,
        timeout: float = 5.0,
        lookup_timeout: float = 6.0,
        verify_tls: bool = True,
        max_response_bytes: int = 1024 * 1024,
        client: httpx.AsyncClient | None = None,
        audit: AuditLogger | None = None,
    ) -> None:
        if create_mode not in CREATE_MODES:
            raise ValueError("create_mode must be one of: " + ", ".join(CREATE_MODES))
        self._token = token.get_secret_value() if isinstance(token, SecretStr) else token
        self._endpoint = f"{url.rstrip('/')}/graphql"
        self._create_mode: CreateMode = create_mode
        self._store = store
        self._cache_ttl = cache_ttl
        self._miss_cache_ttl = miss_cache_ttl
        self._http_timeout = timeout
        self._lookup_timeout = lookup_timeout
        self._verify_tls = verify_tls
        self._max_response_bytes = max_response_bytes
        self._client = (
            client if client is not None else httpx.AsyncClient(timeout=timeout, verify=verify_tls)
        )
        self._owns_client = client is None
        self._audit = audit
        #: Label value -> id, resolved once per process; labels are stable.
        self._label_ids: dict[str, str] = {}

    async def aclose(self) -> None:
        """Close the HTTP client if this client created it."""
        if self._owns_client:
            await self._client.aclose()

    @property
    def create_mode(self) -> CreateMode:
        """The configured write mode; `off` means this client only reads."""
        return self._create_mode

    async def lookup(self, ip: str) -> tuple[OpenCTIIndicator | None, OpenCTIStatus]:
        """Return the indicator for `ip`, or why there is none.

        `not_found` is a real answer and is cached briefly; `unavailable` and
        `unauthorized` are failures the alert renders as "no answer". Redis
        errors propagate to the enricher's fail-soft boundary on purpose:
        bypassing an unavailable cache would silently turn one request per alert
        into one request per event.
        """
        address = public_address(ip)
        if address is None:
            return None, "unavailable"
        deadline = asyncio.get_running_loop().time() + self._lookup_timeout
        try:
            async with asyncio.timeout_at(deadline):
                return await self._singleflight(address, deadline)
        except TimeoutError:
            self._skip("singleflight_timeout")
            return None, "unavailable"
        except RedisError:
            self._skip("store_error")
            raise

    async def create_or_update(
        self,
        ip: str,
        *,
        confidence: int,
        labels: Sequence[str] = (),
        valid_from: datetime | None = None,
    ) -> OpenCTICreateResult:
        """Apply `create_mode` to one address; never raises for a provider fault.

        The lookup runs first and is the only source of truth about existence, so
        a create is preceded by the same exact-pattern search an idempotent
        integration needs. `unavailable`/`unauthorized` stop the pass before any
        write: creating on top of an unanswered lookup is how duplicates and
        blind writes happen.
        """
        if self._create_mode == "off":
            return OpenCTICreateResult("skipped", status="disabled", reason="create_disabled")
        if not 0 <= confidence <= 100:
            raise ValueError("confidence must be between 0 and 100")
        address = public_address(ip)
        if address is None:
            return OpenCTICreateResult("skipped", status="unavailable", reason="not_public")

        moment = stix_datetime(valid_from)
        indicator, status = await self.lookup(str(address))
        if status in ("unavailable", "unauthorized"):
            self._audit_skipped(f"lookup_{status}")
            return OpenCTICreateResult("skipped", status=status, reason=f"lookup_{status}")
        if indicator is None:
            return await self._create(address, confidence=confidence, labels=labels, moment=moment)
        if self._create_mode == "missing":
            return OpenCTICreateResult("existing", indicator=indicator)
        if not indicator.id:
            # Without an id the patch would have nothing to target. Saying so is
            # better than writing to a guessed identifier.
            self._audit_skipped("missing_indicator_id")
            return OpenCTICreateResult(
                "skipped", indicator=indicator, reason="missing_indicator_id"
            )
        return await self._update(
            address, indicator, confidence=confidence, labels=labels, moment=moment
        )

    async def _create(
        self,
        address: ipaddress.IPv4Address | ipaddress.IPv6Address,
        *,
        confidence: int,
        labels: Sequence[str],
        moment: str,
    ) -> OpenCTICreateResult:
        """Create one STIX 2.1 indicator and cache it as the lookup answer."""
        label_ids = await self._resolve_labels(labels) if labels else []
        fields: dict[str, Any] = {
            "name": str(address),
            "pattern": stix_pattern(address),
            "pattern_type": "stix",
            "x_opencti_main_observable_type": main_observable_type(address),
            "valid_from": moment,
            "confidence": confidence,
            "description": INDICATOR_DESCRIPTION,
        }
        # An empty list would clear labels an operator set by hand; omitting the
        # key leaves OpenCTI's own defaults alone.
        if label_ids:
            fields["objectLabel"] = label_ids
        mutation = await self._mutate(ADD_INDICATOR_MUTATION, {"input": fields}, operation="create")
        if mutation.reason is not None:
            self._audit_failure(mutation.reason, operation="create")
            return OpenCTICreateResult("failed", status=mutation.status, reason=mutation.reason)
        indicator = (
            _indicator(mutation.node)
            if mutation.node is not None
            else OpenCTIIndicator(
                pattern=fields["pattern"],
                confidence=confidence,
                valid_from=moment,
                labels=tuple(labels),
            )
        )
        await self._write_cache(str(address), indicator, ttl=self._cache_ttl)
        self._audit_create("created")
        return OpenCTICreateResult("created", indicator=indicator)

    async def _update(
        self,
        address: ipaddress.IPv4Address | ipaddress.IPv6Address,
        existing: OpenCTIIndicator,
        *,
        confidence: int,
        labels: Sequence[str],
        moment: str,
    ) -> OpenCTICreateResult:
        """Patch confidence, `valid_from` and labels of an existing indicator."""
        label_ids = await self._resolve_labels(labels) if labels else []
        patch: list[dict[str, Any]] = [
            {"key": "confidence", "value": [str(confidence)]},
            {"key": "valid_from", "value": [moment]},
        ]
        if label_ids:
            patch.append({"key": "objectLabel", "value": label_ids})
        mutation = await self._mutate(
            PATCH_INDICATOR_MUTATION,
            {"id": existing.id, "input": patch},
            operation="update",
        )
        if mutation.reason is not None:
            self._audit_failure(mutation.reason, operation="update")
            # The platform still holds the old indicator: report it so the alert
            # shows what OpenCTI actually knows, not what we tried to write.
            return OpenCTICreateResult(
                "failed", indicator=existing, status=mutation.status, reason=mutation.reason
            )
        indicator = (
            _indicator(mutation.node)
            if mutation.node is not None
            else OpenCTIIndicator(
                id=existing.id,
                pattern=existing.pattern,
                confidence=confidence,
                created_at=existing.created_at,
                valid_from=moment,
                labels=tuple(labels) or existing.labels,
            )
        )
        await self._write_cache(str(address), indicator, ttl=self._cache_ttl)
        self._audit_create("updated")
        return OpenCTICreateResult("updated", indicator=indicator)

    async def _mutate(
        self,
        query: str,
        variables: dict[str, Any],
        *,
        operation: Literal["create", "update"],
    ) -> _Mutation:
        """POST one mutation once. No retry: a write is not safely repeatable here."""
        budget = max(0.0, self._lookup_timeout * 0.8)
        try:
            response = await self._http_request({"query": query, "variables": variables}, budget)
        except (httpx.HTTPError, TimeoutError):
            return _Mutation(reason="timeout", status="unavailable")
        if response.status_code in (401, 403):
            return _Mutation(reason="unauthorized", status="unauthorized")
        if response.status_code != 200:
            return _Mutation(reason="http_error", status="unavailable")
        if len(response.content) > self._max_response_bytes:
            self._skip("response_too_large")
            return _Mutation(reason="response_too_large", status="unavailable")
        try:
            node = _mutation_object(response.json(), _mutation_field(operation))
        except (ValueError, TypeError, KeyError, AttributeError):
            return _Mutation(reason="invalid_response", status="unavailable")
        return _Mutation(node=node)

    async def _resolve_labels(self, labels: Sequence[str]) -> list[str]:
        """Resolve label values to OpenCTI ids, creating labels that do not exist.

        A label that cannot be resolved is skipped and audited instead of failing
        the write: the indicator is the product, the label is metadata, and a
        missing label must not turn an alert into a skipped create.
        """
        resolved: list[str] = []
        for name in labels:
            cached = self._label_ids.get(name)
            if cached is not None:
                resolved.append(cached)
                continue
            identifier = await self._find_label(name)
            if identifier is None:
                identifier = await self._create_label(name)
            if identifier is None:
                self._skip("label_unavailable")
                continue
            self._label_ids[name] = identifier
            resolved.append(identifier)
        return resolved

    async def _find_label(self, name: str) -> str | None:
        """Return the id of an existing label, or None when it is absent."""
        payload = await self._graphql(
            LABEL_QUERY,
            {
                "filters": {
                    "mode": "and",
                    "filterGroups": [],
                    "filters": [{"key": "value", "values": [name], "operator": "eq"}],
                }
            },
        )
        if payload is None:
            return None
        try:
            return _label_id(payload)
        except (ValueError, TypeError, KeyError, AttributeError):
            return None

    async def _create_label(self, name: str) -> str | None:
        """Create one label and return its id, or None when that fails."""
        payload = await self._graphql(ADD_LABEL_MUTATION, {"input": {"value": name}})
        if payload is None:
            return None
        try:
            return _created_label_id(payload)
        except (ValueError, TypeError, KeyError, AttributeError):
            return None

    async def _graphql(self, query: str, variables: dict[str, Any]) -> object | None:
        """POST one auxiliary document; None means it did not answer usefully."""
        try:
            response = await self._http_request(
                {"query": query, "variables": variables},
                max(0.0, self._lookup_timeout * 0.8),
            )
        except (httpx.HTTPError, TimeoutError):
            return None
        if response.status_code != 200 or len(response.content) > self._max_response_bytes:
            return None
        try:
            return cast("object", response.json())
        except ValueError:
            return None

    async def _singleflight(
        self,
        address: ipaddress.IPv4Address | ipaddress.IPv6Address,
        deadline: float,
    ) -> tuple[OpenCTIIndicator | None, OpenCTIStatus]:
        """One request per address at a time, shared through a Redis lease."""
        loop = asyncio.get_running_loop()
        canonical = str(address)
        initial = True
        while True:
            hit, indicator = await self._read_cache(canonical)
            if initial:
                result = ("hit" if indicator is not None else "negative_hit") if hit else "miss"
                metrics.ENRICHMENT_CACHE.labels(provider=self.name, result=result).inc()
                initial = False
            if hit:
                return indicator, ("ok" if indicator is not None else "not_found")
            # The owner must finish before its lease expires; the extra second
            # covers the request budget rounding.
            ttl_ms = max(1, math.ceil((deadline - loop.time()) * 1000)) + 1000
            lease = AsyncExitStack()
            try:
                acquired = await lease.enter_async_context(
                    self._store.lock(
                        keys.enrichment_lock_key(PROVIDER, canonical), ttl_ms=ttl_ms, wait_timeout=0
                    )
                )
                if acquired:
                    # Another owner may have filled the cache between our read
                    # and SET NX, so the cache is checked again before asking.
                    hit, indicator = await self._read_cache(canonical)
                    if hit:
                        return indicator, ("ok" if indicator is not None else "not_found")
                    return await self._request(address, deadline)
            finally:
                # A timed-out request must not wait for an unresponsive Redis
                # while unlocking. The lease's TTL is the recovery fallback.
                try:
                    async with asyncio.timeout_at(deadline):
                        await lease.aclose()
                except TimeoutError:
                    pass
            await asyncio.sleep(0.01)

    async def _request(
        self,
        address: ipaddress.IPv4Address | ipaddress.IPv6Address,
        deadline: float,
    ) -> tuple[OpenCTIIndicator | None, OpenCTIStatus]:
        """Ask OpenCTI once and cache whatever the answer was."""
        try:
            # Leave part of the budget for writing the cache entry.
            remaining = deadline - asyncio.get_running_loop().time()
            request_budget = min(self._http_timeout, max(0.0, remaining * 0.8))
            response = await self._http_request(_lookup_payload(address), request_budget)
        except (httpx.HTTPError, TimeoutError):
            return None, "unavailable"

        if response.status_code in (401, 403):
            self._audit_failure("unauthorized", status="error")
            return None, "unauthorized"
        if response.status_code != 200:
            self._audit_failure("http_error")
            return None, "unavailable"
        if len(response.content) > self._max_response_bytes:
            # The body is already in memory; refusing to parse it is what keeps
            # an oversized or hostile answer out of the JSON decoder.
            self._skip("response_too_large")
            return None, "unavailable"
        try:
            indicator = _parse(response.json())
        except (ValueError, TypeError, KeyError, AttributeError):
            self._audit_failure("invalid_response")
            return None, "unavailable"
        await self._write_cache(
            str(address),
            indicator,
            ttl=self._cache_ttl if indicator is not None else self._miss_cache_ttl,
        )
        return indicator, ("ok" if indicator is not None else "not_found")

    async def _http_request(self, payload: dict[str, Any], budget: float) -> httpx.Response:
        """POST one GraphQL document, counting only an actual HTTP attempt."""
        outcome = "cancelled"
        try:
            async with asyncio.timeout(budget):
                response = await self._client.post(
                    self._endpoint,
                    json=payload,
                    headers={"Authorization": f"Bearer {self._token}"},
                )
            if response.status_code == 200:
                outcome = "ok"
            elif response.status_code in (401, 403):
                outcome = "unauthorized"
            else:
                outcome = "http_error"
            return response
        except (httpx.TimeoutException, TimeoutError):
            outcome = "timeout"
            raise
        except httpx.HTTPError:
            outcome = "network_error"
            raise
        finally:
            metrics.ENRICHMENT_REQUESTS.labels(provider=self.name, outcome=outcome).inc()

    # --- Cache --------------------------------------------------------------

    async def _read_cache(self, ip: str) -> tuple[bool, OpenCTIIndicator | None]:
        """Return `(hit, indicator)`; a cached "not found" is a hit without one."""
        raw = await self._store.get_value(keys.enrichment_cache_key(PROVIDER, ip))
        if not raw:
            return False, None
        try:
            entry = _CacheEntry.model_validate_json(raw)
        except ValidationError:
            return False, None
        return True, entry.indicator

    async def _write_cache(
        self,
        ip: str,
        indicator: OpenCTIIndicator | None,
        *,
        ttl: float,
    ) -> None:
        if ttl <= 0:
            return
        entry = _CacheEntry(found=indicator is not None, indicator=indicator)
        await self._store.set_with_ttl(
            keys.enrichment_cache_key(PROVIDER, ip), entry.model_dump_json(), ttl=ttl
        )

    # --- Audit --------------------------------------------------------------

    def _skip(self, reason: str) -> None:
        metrics.ENRICHMENT_SKIPPED.labels(provider=self.name, reason=reason).inc()
        if self._audit is not None:
            self._audit.emit(
                "enrichment_request_skipped", "info", {"provider": self.name, "reason": reason}
            )

    def _audit_failure(
        self,
        reason: str,
        *,
        operation: Literal["create", "update"] | None = None,
        status: Literal["warning", "error"] = "warning",
    ) -> None:
        details: dict[str, object] = {"reason": reason}
        if operation is not None:
            details["operation"] = operation
        if self._audit is not None:
            self._audit.emit("opencti_failed", status, details)

    def _audit_create(self, outcome: Literal["created", "updated"]) -> None:
        if self._audit is not None:
            self._audit.emit("opencti_create", "success", {"outcome": outcome})

    def _audit_skipped(self, reason: str) -> None:
        if self._audit is not None:
            self._audit.emit("opencti_create_skipped", "info", {"reason": reason})


def _lookup_payload(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> dict[str, Any]:
    """The lookup document plus its exact-pattern filter."""
    return {
        "query": INDICATOR_QUERY,
        "variables": {
            "filters": {
                "mode": "and",
                "filterGroups": [],
                "filters": [
                    {
                        "key": "pattern",
                        "values": [stix_pattern(address)],
                        "operator": "eq",
                    }
                ],
            }
        },
    }


def _mutation_field(operation: Literal["create", "update"]) -> str:
    """The payload field a mutation returns; `create` and `update` differ."""
    return "indicatorAdd" if operation == "create" else "indicatorFieldPatch"


def _parse(payload: object) -> OpenCTIIndicator | None:
    """Extract the first indicator, or None when OpenCTI knows no match."""
    if not isinstance(payload, dict):
        raise ValueError("invalid GraphQL envelope")
    if payload.get("errors"):
        # A GraphQL error is a failed query, not "no indicator": reporting it as
        # not_found would let an operator believe the address is clean.
        raise ValueError("GraphQL query failed")
    data = payload.get("data")
    if not isinstance(data, dict):
        raise ValueError("invalid GraphQL data")
    connection = data.get("indicators")
    if not isinstance(connection, dict):
        raise ValueError("invalid indicators connection")
    edges = connection.get("edges")
    if not isinstance(edges, list):
        raise ValueError("invalid indicators edges")
    if not edges:
        return None
    head = edges[0]
    node = head.get("node") if isinstance(head, dict) else None
    if not isinstance(node, dict):
        raise ValueError("invalid indicator node")
    return _indicator(node)


def _mutation_object(payload: object, field: str) -> dict[str, Any] | None:
    """Return the object a mutation wrote, or None when it returned none."""
    if not isinstance(payload, dict):
        raise ValueError("invalid GraphQL envelope")
    if payload.get("errors"):
        raise ValueError("GraphQL mutation failed")
    data = payload.get("data")
    if not isinstance(data, dict):
        raise ValueError("invalid GraphQL data")
    node = data.get(field)
    if node is None:
        return None
    if not isinstance(node, dict):
        raise ValueError("invalid mutation payload")
    return node


def _indicator(node: dict[str, Any]) -> OpenCTIIndicator:
    """Map one OpenCTI node onto the alert model, ignoring odd field types."""
    confidence = node.get("confidence")
    try:
        confidence_value = int(confidence) if confidence is not None else None
    except (TypeError, ValueError):
        confidence_value = None
    return OpenCTIIndicator(
        id=_text(node.get("id")),
        pattern=_text(node.get("pattern")),
        confidence=confidence_value,
        created_at=_text(node.get("created_at")) or None,
        valid_from=_text(node.get("valid_from")) or None,
    )


def _label_id(payload: object) -> str | None:
    """Return the id of the first label in a `labels` connection."""
    data = _data(payload)
    connection = data.get("labels")
    if not isinstance(connection, dict):
        raise ValueError("invalid labels connection")
    edges = connection.get("edges")
    if not isinstance(edges, list):
        raise ValueError("invalid labels edges")
    if not edges:
        return None
    head = edges[0]
    node = head.get("node") if isinstance(head, dict) else None
    if not isinstance(node, dict):
        raise ValueError("invalid label node")
    identifier = node.get("id")
    return identifier if isinstance(identifier, str) and identifier else None


def _created_label_id(payload: object) -> str | None:
    """Return the id of the label `labelAdd` created."""
    data = _data(payload)
    node = data.get("labelAdd")
    if node is None:
        return None
    if not isinstance(node, dict):
        raise ValueError("invalid label mutation payload")
    identifier = node.get("id")
    return identifier if isinstance(identifier, str) and identifier else None


def _data(payload: object) -> dict[str, Any]:
    """Return the `data` object of a GraphQL envelope, or raise."""
    if not isinstance(payload, dict):
        raise ValueError("invalid GraphQL envelope")
    if payload.get("errors"):
        raise ValueError("GraphQL query failed")
    data = payload.get("data")
    if not isinstance(data, dict):
        raise ValueError("invalid GraphQL data")
    return data


def _text(value: object) -> str:
    """Return a string field, or an empty string for anything unexpected."""
    return value if isinstance(value, str) else ""


__all__ = [
    "ADD_INDICATOR_MUTATION",
    "ADD_LABEL_MUTATION",
    "CREATE_MODES",
    "INDICATOR_DESCRIPTION",
    "INDICATOR_QUERY",
    "LABEL_QUERY",
    "PATCH_INDICATOR_MUTATION",
    "CreateMode",
    "CreateOutcome",
    "OpenCTIClient",
    "OpenCTICreateResult",
    "main_observable_type",
    "stix_datetime",
    "stix_pattern",
]
