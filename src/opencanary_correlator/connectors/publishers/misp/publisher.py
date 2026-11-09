"""Durable MISP publisher wired to incidents, a Redis queue and the API client."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Final, cast
from uuid import UUID

from opencanary_correlator.audit import AuditLogger
from opencanary_correlator.config import Settings
from opencanary_correlator.connectors.base import IncidentLike
from opencanary_correlator.connectors.publishers.base import BasePublisher
from opencanary_correlator.connectors.publishers.misp.builder import MispEventBuilder
from opencanary_correlator.connectors.publishers.misp.client import (
    MispClient,
    MispClientError,
)
from opencanary_correlator.connectors.publishers.misp.identity import (
    ObservationIncident,
    observation_from_incident,
)
from opencanary_correlator.connectors.publishers.misp.models import (
    MispEvent,
    MispExistingEvent,
    MispWindow,
    MispWindowResult,
    window_bounds,
)
from opencanary_correlator.connectors.publishers.misp.queue import MispObservationQueue
from opencanary_correlator.metrics import (
    MISP_OBSERVATIONS,
    MISP_PENDING,
    MISP_PUBLICATIONS,
)
from opencanary_correlator.storage.redis_store import RedisStore

_logger = logging.getLogger(__name__)

_DEFAULT_RETENTION: Final[int] = 14 * 24 * 3600


class MispPublisherError(RuntimeError):
    """A window cannot be published yet, usually because preflight failed."""


class MispPublisher(BasePublisher):
    """Turn eligible incidents into one aggregate MISP event per UTC window.

    The publisher is fail-soft from the engine's point of view: `observe` writes
    a durable queue row and never raises. The background worker retries a window
    that failed to publish, and acknowledges it only after the event and its
    attributes were created.
    """

    name = "misp"

    def __init__(
        self,
        *,
        settings: Settings,
        store: RedisStore,
        audit: AuditLogger,
        client: MispClient | None = None,
        queue: MispObservationQueue | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if settings.misp_url is None or settings.misp_api_key is None:
            raise MispPublisherError("MISP publisher requires a URL and API key")
        self._settings = settings
        self._audit = audit
        self._client = client or MispClient(
            url=settings.misp_url,
            api_key=settings.misp_api_key.get_secret_value(),
            verify_tls=settings.misp_verify_tls,
            timeout=settings.misp_timeout,
            max_response_bytes=settings.misp_max_response_bytes,
        )
        self._queue = queue or MispObservationQueue(
            store,
            retention_seconds=max(_DEFAULT_RETENTION, settings.misp_event_window * 2),
            max_observations_per_window=settings.misp_max_observations_per_window,
        )
        self._clock = clock or (lambda: datetime.now(UTC))
        self._builder = MispEventBuilder(
            namespace=settings.misp_event_namespace,
            distribution=settings.misp_distribution,
            sharing_group_id=settings.misp_sharing_group_id,
            tlp=settings.misp_tlp,
            pap=settings.misp_pap,
            confidence_tag=settings.misp_confidence_tag,
            source_tags=tuple(settings.misp_tags),
            to_ids_types=frozenset(settings.misp_to_ids_types),
            to_ids_min_events=settings.misp_to_ids_min_events,
        )
        self._protected = frozenset(settings.notification_redact_values)
        self._task: asyncio.Task[None] | None = None
        self._stopping = False

    @property
    def critical_tasks(self) -> tuple[asyncio.Task[None], ...]:
        return (self._task,) if self._task is not None else ()

    async def start(self) -> None:
        if self._task is not None:
            return
        self._stopping = False
        self._task = asyncio.create_task(self._run_loop(), name="misp-publisher")

    async def stop(self) -> None:
        self._stopping = True
        task = self._task
        self._task = None
        if task is None:
            return
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    async def aclose(self) -> None:
        await self._client.aclose()

    async def observe(self, incident: IncidentLike) -> None:
        """Queue one incident observation; never propagate a failure into ingest."""
        observation = observation_from_incident(
            cast(ObservationIncident, incident),
            protected_addresses=self._protected,
        )
        if observation is None:
            MISP_OBSERVATIONS.labels(result="skipped").inc()
            return
        start, end = window_bounds(observation.last_seen, self._settings.misp_event_window)
        try:
            accepted = await self._queue.enqueue(start, end, observation)
        except Exception as exc:
            MISP_OBSERVATIONS.labels(result="error").inc()
            self._audit.emit(
                "misp_enqueue_failed",
                "error",
                {"error_type": type(exc).__name__},
            )
            return
        if not accepted:
            MISP_OBSERVATIONS.labels(result="window_full").inc()
            self._audit.emit(
                "misp_window_full",
                "warning",
                {
                    "window": start.isoformat(),
                    "limit": self._settings.misp_max_observations_per_window,
                },
            )
            return
        MISP_OBSERVATIONS.labels(result="queued").inc()

    async def run_once(self) -> int:
        """Flush due windows once, returning how many were successfully published."""
        now = self._clock().astimezone(UTC)
        pending = await self._queue.pending(
            now, limit=max(1, self._settings.misp_max_observations_per_window)
        )
        processed = 0
        for start in pending:
            end = await self._queue.window_end(start)
            if end is None:
                continue
            if end + timedelta(seconds=self._settings.misp_publish_grace) > now:
                continue
            try:
                await self._process_window(start, end)
            except Exception as exc:
                self._audit.emit(
                    "misp_publish_failed",
                    "error",
                    {
                        "window": start.isoformat(),
                        "error_type": type(exc).__name__,
                        "reason": getattr(exc, "reason", "publish_failed"),
                    },
                )
                continue
            processed += 1
        MISP_PENDING.set(await self._queue.pending_count())
        return processed

    async def _run_loop(self) -> None:
        while not self._stopping:
            try:
                await self.run_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self._audit.emit(
                    "misp_worker_failed",
                    "error",
                    {"error_type": type(exc).__name__},
                )
                _logger.warning("MISP worker iteration failed: %s", type(exc).__name__)
            await asyncio.sleep(self._settings.misp_flush_interval)

    async def _process_window(self, start: datetime, end: datetime) -> MispWindowResult:
        observations = await self._queue.read(start)
        if not observations:
            await self._queue.ack(start)
            return MispWindowResult(window_start=start)

        enabled = await self._client.warninglists_enabled()
        if enabled == 0 and self._settings.misp_warninglist_required:
            raise MispPublisherError("warninglists_disabled")
        matches = await self._client.check_warninglists([item.ip for item in observations])
        clean = [item for item in observations if item.ip not in matches]
        skipped = len(observations) - len(clean)
        if not clean:
            await self._queue.ack(start)
            self._audit.emit(
                "misp_window_skipped",
                "warning",
                {"window": start.isoformat(), "warninglisted": skipped},
            )
            return MispWindowResult(
                window_start=start, skipped=skipped, total_events=sum(i.count for i in observations)
            )
        if skipped:
            self._audit.emit(
                "misp_warninglist_filtered",
                "info",
                {"window": start.isoformat(), "skipped": skipped},
            )

        # Sighting-first: an address the community already has is observed on
        # the existing attribute; only genuinely new addresses go into today's
        # aggregate event. The search is exact on value and type even if the
        # MISP build applies wildcard semantics to restSearch.
        known = await self._client.find_ip_attributes([item.ip for item in clean])
        new_observations = tuple(item for item in clean if item.ip not in known)
        # Build the deterministic event identity even when every address is
        # already known: a previous attempt may have created our daily event but
        # failed before publish, and that event still has to be resumed.
        event = self._builder.build(MispWindow(start=start, end=end, observations=new_observations))
        existing = await self._client.find_event(event.uuid)
        # A sighting creates no event, so it does not need event-level handling
        # tags. Resolve them only when this window has a new address or a daily
        # event to finish.
        tag_ids = (
            await self._resolve_tags(self._builder.tags)
            if new_observations or existing is not None
            else {}
        )
        event_id: int | None = None
        event_uuid: UUID | None = None
        added = 0
        published = False
        if existing is None:
            if new_observations:
                event_id, event_uuid, added = await self._create_event(event, tag_ids)
                published = event.published
        else:
            existing_id = existing.id
            if existing_id is None:
                raise MispPublisherError("existing_event_without_id")
            event_id = existing_id
            event_uuid = existing.uuid
            if new_observations:
                added = await self._add_missing_attributes(event_id, event, existing)
            await self._add_missing_tags(event_id, tag_ids, existing.tags)
            published = existing.published

        # Write the event first, then its sightings. A sighting failure after a
        # successful create therefore retries idempotently against the existing
        # event instead of creating a second daily event.
        sightings = await self._client.add_sighting(tuple(sorted(known)))

        if self._settings.misp_publish_mode == "auto" and event_id is not None and not published:
            await self._client.publish_event(event_id)
            published = True

        await self._queue.ack(start)
        total_events = sum(item.count for item in clean)
        if event_id is None:
            MISP_PUBLICATIONS.labels(result="sighted").inc()
            self._audit.emit(
                "misp_window_sighted",
                "success",
                {
                    "window": start.isoformat(),
                    "sightings": sightings,
                    "warninglisted": skipped,
                },
            )
        else:
            MISP_PUBLICATIONS.labels(result="published" if published else "draft").inc()
            self._audit.emit(
                "misp_window_published",
                "success",
                {
                    "window": start.isoformat(),
                    "event_id": event_id,
                    "attributes": added,
                    "sightings": sightings,
                    "warninglisted": skipped,
                    "published": published,
                },
            )
        return MispWindowResult(
            window_start=start,
            event_uuid=event_uuid,
            event_id=event_id,
            attributes=added,
            sightings=sightings,
            skipped=skipped,
            published=published,
            total_events=total_events,
        )

    async def _resolve_tags(self, tags: tuple[str, ...]) -> dict[str, str]:
        resolved: dict[str, str] = {}
        for tag in dict.fromkeys(tags):
            found = await self._client.search_tag(tag)
            if found is None:
                raise MispPublisherError("missing_tag")
            resolved[tag] = found
        return resolved

    async def _create_event(
        self, event: MispEvent, tag_ids: dict[str, str]
    ) -> tuple[int, UUID, int]:
        created = event.model_copy(update={"attributes": ()})
        event_id, event_uuid = await self._client.add_event(created)
        added = 0
        for attribute in event.attributes:
            await self._client.add_attribute(event_id, attribute)
            added += 1
        for tag_id in tag_ids.values():
            await self._client.add_event_tag(event_id, tag_id)
        return event_id, event_uuid, added

    async def _add_missing_attributes(
        self, event_id: int, event: MispEvent, existing: MispExistingEvent
    ) -> int:
        added = 0
        for attribute in event.attributes:
            if attribute.value in existing.attribute_values:
                continue
            try:
                await self._client.add_attribute(event_id, attribute)
            except MispClientError as exc:
                # A previous attempt may have created the attribute after our
                # GET but before this POST. MISP reports the duplicate as 422;
                # treating it as success keeps the retry idempotent.
                if exc.status_code != 422:
                    raise
            added += 1
        return added

    async def _add_missing_tags(
        self, event_id: int, tag_ids: dict[str, str], existing: frozenset[str]
    ) -> None:
        for name, tag_id in tag_ids.items():
            if name in existing:
                continue
            try:
                await self._client.add_event_tag(event_id, tag_id)
            except MispClientError as exc:
                if exc.status_code != 422:
                    raise


__all__ = ["MispPublisher", "MispPublisherError"]
