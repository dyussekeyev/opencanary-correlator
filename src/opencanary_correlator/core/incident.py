"""Incident persistence: create-or-merge incidents in Redis under a lock.

Incident hashes keep the exact field names and value shapes the legacy console
reads (`events_list` as a CSV of epochs, `logdata` as a JSON string, booleans
stored as ``"True"``/``"False"``). Creation and merging are serialised through
a Redis lock so two replicas can never both notify about the same incident.

The domain model lives in `opencanary_correlator.core.incident_model` and is
re-exported here so existing imports keep working.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from typing import Any, Final

from opencanary_correlator.audit import AuditLogger
from opencanary_correlator.config import Settings
from opencanary_correlator.constants import DEFAULT_LOGTYPE
from opencanary_correlator.core.incident_model import (
    INCIDENT_TYPES,
    Incident,
    IncidentFTPLogin,
    IncidentHostPortScan,
    IncidentHTTPLogin,
    IncidentHTTPProxy,
    IncidentHTTPRequest,
    IncidentMSSQLLogin,
    IncidentMySQLLogin,
    IncidentNetworkPortScan,
    IncidentNTPMonList,
    IncidentRDPLogin,
    IncidentSIPLogin,
    IncidentSMBFileOpen,
    IncidentSNMP,
    IncidentSSHLogin,
    IncidentTelnetLogin,
    IncidentTFTP,
    IncidentVNCLogin,
)
from opencanary_correlator.schemas import CanaryEvent
from opencanary_correlator.storage import keys
from opencanary_correlator.storage.redis_store import RedisStore

logger = logging.getLogger(__name__)

_UNSET: Final[object] = object()

__all__ = [
    "DEFAULT_LOGTYPE",
    "INCIDENT_TYPES",
    "Incident",
    "IncidentFTPLogin",
    "IncidentHTTPLogin",
    "IncidentHTTPProxy",
    "IncidentHTTPRequest",
    "IncidentHostPortScan",
    "IncidentMSSQLLogin",
    "IncidentMySQLLogin",
    "IncidentNTPMonList",
    "IncidentNetworkPortScan",
    "IncidentRDPLogin",
    "IncidentRepository",
    "IncidentSIPLogin",
    "IncidentSMBFileOpen",
    "IncidentSNMP",
    "IncidentSSHLogin",
    "IncidentTFTP",
    "IncidentTelnetLogin",
    "IncidentVNCLogin",
]


class IncidentRepository:
    """Create or merge incidents in Redis, exactly once per source host."""

    def __init__(
        self,
        store: RedisStore,
        settings: Settings,
        audit: AuditLogger,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._store = store
        self._settings = settings
        self._audit = audit
        self._clock = clock

    async def record(
        self,
        incident_name: str,
        event: CanaryEvent,
        *,
        logdata: Any = _UNSET,
        logtype: int | None = None,
    ) -> Incident | None:
        """Persist a new incident, or merge into the live one.

        Returns the incident only when it was created: merged events must not
        trigger another notification.
        """
        incident_cls = INCIDENT_TYPES[incident_name]
        now = int(self._clock())
        horizon = self._settings.horizon_for(incident_name)
        # The trailing colon is part of the key grammar: matching only the host
        # prefix would also match hosts that merely start with it (10.0.0.5
        # would merge into an incident for 10.0.0.55).
        prefix = f"{keys.incident_prefix(incident_name, event.src_host)}:"
        pointer_key = keys.incident_latest_key(incident_name, event.src_host)
        new_logdata = event.logdata if logdata is _UNSET else logdata
        resolved_logtype = logtype if logtype is not None else int(event.logtype)

        async with self._store.lock(
            keys.incident_lock_key(incident_name, event.src_host)
        ) as acquired:
            if not acquired:
                self._audit.emit(
                    "incident_lock_timeout",
                    "error",
                    {"incident": incident_name, "src_host": event.src_host},
                )
                return None

            scan_limit = self._settings.incident_lookup_scan_limit
            lookup = await self._store.find_recent_incident(
                prefix,
                min_score=now - horizon,
                pointer_key=pointer_key,
                scan_limit=scan_limit,
            )
            if lookup.key is None and lookup.truncated:
                # The capped scan missed, but a live incident for this host can
                # sit behind the cap (a pointerless incident from an older build).
                # Creating a second one would duplicate the alert and the
                # notification, so read the whole horizon window before deciding.
                lookup = await self._store.find_recent_incident(
                    prefix,
                    min_score=now - horizon,
                    pointer_key=None,
                    scan_limit=None,
                )
            existing_key = lookup.key
            if existing_key is not None:
                fields = await self._store.hgetall(existing_key)
                if fields:
                    cap = self._settings.max_stored_events
                    merged = incident_cls.from_fields(existing_key, fields)
                    # A stored incident is frozen once its timestamp list is full.
                    # The flag plus a count already at the cap answer that without
                    # splitting the CSV, and when the cap was raised in the
                    # meantime the count is below it, so recording resumes.
                    frozen = merged.events_truncated and merged.events_count >= cap
                    if not frozen:
                        merged.events_list, appended = incident_cls.append_timestamp(
                            merged.events_list, now, limit=cap
                        )
                        frozen = not appended
                    merged.events_count += 1
                    merged.updated = True
                    merged.events_truncated = merged.events_truncated or frozen
                    if frozen and incident_cls.LOG_DATA_IS_APPEND_ONLY:
                        # One event adds one timestamp and one log entry, capped at
                        # the same limit, so a full timestamp list means
                        # `merge_logdata` would decode the whole stored list (44-46
                        # us of a ~51 us merge) only to return it unchanged. For a
                        # frozen history the decode is discarded, so it is skipped.
                        logdata_changed = False
                    else:
                        stored_logdata = incident_cls.merge_logdata(
                            merged.logdata, new_logdata, limit=cap
                        )
                        logdata_changed = stored_logdata != (merged.logdata or "")
                        merged.logdata = stored_logdata
                    if merged.events_truncated:
                        # The stored history is full: send the counters only, so a
                        # 10k-event incident stops costing a full-field rewrite
                        # (and a full-field replication) on every event.
                        updates: dict[str, str] = {
                            "events_count": str(merged.events_count),
                            "events_truncated": "True",
                            "updated": "True",
                        }
                        if not frozen:
                            updates["events_list"] = merged.events_list
                        if logdata_changed:
                            updates["logdata"] = merged.logdata or "[]"
                    else:
                        updates = merged.to_fields()
                    await self._store.save_incident(
                        existing_key,
                        updates,
                        score=now,
                        pointer_key=pointer_key,
                    )
                    self._audit.emit(
                        "incident_updated",
                        "info",
                        {
                            "incident": incident_name,
                            "key": existing_key,
                            "events_count": merged.events_count,
                            "events_truncated": merged.events_truncated,
                        },
                    )
                    return None

            key = keys.incident_key(incident_name, event.src_host, now)
            cap = self._settings.max_stored_events
            initial_logdata = incident_cls.trim_logdata(
                incident_cls.serialize_logdata(new_logdata), limit=cap
            )
            incident = incident_cls(
                key=key,
                node_id=event.node_id,
                src_host=event.src_host,
                src_port=event.src_port,
                dst_host=event.dst_host,
                dst_port=event.dst_port,
                logtype=resolved_logtype,
                created=now,
                events_list=str(now),
                events_count=1,
                logdata=initial_logdata,
                description=incident_cls.DESCRIPTION,
            )
            await self._store.save_incident(
                key, incident.to_fields(), score=now, pointer_key=pointer_key
            )
            self._audit.emit(
                "incident_created",
                "info",
                {
                    "incident": incident_name,
                    "key": key,
                    "node_id": event.node_id,
                    "src_host": event.src_host,
                },
            )
            return incident
