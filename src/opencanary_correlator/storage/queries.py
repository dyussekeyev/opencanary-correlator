"""Read-side queries shared with the legacy console.

Field names and value shapes intentionally match `common/queries.py` from the
Python 2 implementation: `created` stays a string, `events_list` is returned in
milliseconds, `logdata` is decoded and capped at 100 entries.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from typing import Any

from opencanary_correlator.constants import (
    KEY_CONSOLE_SETTING_PREFIX,
    KEY_INCIDENTS,
    KEY_LOGS,
    MAX_EVENT_COUNT,
)
from opencanary_correlator.storage.keys import device_key
from opencanary_correlator.storage.redis_store import RedisStore
from opencanary_correlator.utils.time import (
    current_time_offset,
    timestamp_age,
    timestamp_js,
    timestamp_printable,
)

logger = logging.getLogger(__name__)

MAX_LOG_ENTRIES = 1000


def _as_int(value: Any) -> int:
    """Parse a stored integer field, tolerating the legacy shapes."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _jsonify_incident(
    key: str,
    incident: dict[str, str],
    *,
    host: dict[str, str] | None,
) -> dict[str, Any]:
    """Convert stored hash fields into the JSON shape the console expects."""
    payload: dict[str, Any] = dict(incident)
    payload["key"] = key

    created = float(incident.get("created", 0))
    payload["created_printable"] = timestamp_printable(created)
    payload["created_age"] = timestamp_age(created)
    payload["created_age_seconds"] = float(current_time_offset()) - created

    raw_events = incident.get("events_list", "")
    events = raw_events.split(",") if raw_events else []
    rendered = events[:MAX_EVENT_COUNT]
    payload["events_list_printable"] = ",".join(timestamp_printable(event) for event in rendered)
    payload["events_list"] = [timestamp_js(event) for event in rendered]
    # The counter is exact even though storage is capped, so the console still
    # reports how many events an incident really has. Incidents written before
    # the counter existed fall back to the stored list length.
    total_events = _as_int(incident.get("events_count"))
    if total_events > len(rendered):
        payload["events_skipped"] = total_events - len(rendered)
    elif len(events) > MAX_EVENT_COUNT:
        payload["events_skipped"] = len(events) - MAX_EVENT_COUNT

    if "events_truncated" in payload:
        payload["events_truncated"] = str(payload["events_truncated"]).lower() == "true"

    if "logdata" in incident:
        try:
            logdata = json.loads(incident["logdata"])
        except (TypeError, json.JSONDecodeError):
            logdata = incident["logdata"]
        if isinstance(logdata, list):
            logdata = logdata[:MAX_EVENT_COUNT]
        payload["logdata"] = logdata

    if host is not None:
        payload["host"] = host
    return payload


async def _filter_incidents(
    store: RedisStore,
    predicate: Callable[[dict[str, str]], bool],
    *,
    include_hosts: bool = True,
) -> list[dict[str, Any]]:
    host_cache: dict[str, dict[str, str]] = {}
    incidents: list[dict[str, Any]] = []
    for key in await store.zrangebyscore(KEY_INCIDENTS, "-inf", "+inf"):
        fields = await store.hgetall(key)
        if not fields:
            continue
        try:
            if not predicate(fields):
                continue
            host: dict[str, str] | None = None
            if include_hosts:
                node_id = fields.get("node_id", "")
                if node_id not in host_cache:
                    host_cache[node_id] = await store.hgetall(device_key(node_id))
                host = host_cache[node_id]
            incidents.append(_jsonify_incident(key, fields, host=host))
        except (KeyError, TypeError, ValueError):
            logger.warning("could not render incident %s", key, exc_info=True)
    return incidents


async def get_all_incidents(
    store: RedisStore,
    *,
    include_hosts: bool = True,
    node_id: str | None = None,
) -> list[dict[str, Any]]:
    """Return every incident, newest last, optionally filtered by node."""
    if node_id is None:
        return await _filter_incidents(store, lambda _fields: True, include_hosts=include_hosts)
    return await _filter_incidents(
        store,
        lambda fields: fields.get("node_id") == node_id,
        include_hosts=include_hosts,
    )


async def get_incident(store: RedisStore, key: str) -> dict[str, Any] | None:
    """Return one incident with its host, or None when it is gone."""
    fields = await store.hgetall(key)
    if not fields:
        return None
    host = await store.hgetall(device_key(fields.get("node_id", "")))
    return _jsonify_incident(key, fields, host=host)


async def get_unacknowledged_incidents(
    store: RedisStore,
    *,
    include_hosts: bool = True,
    node_id: str | None = None,
) -> list[dict[str, Any]]:
    """Return incidents that have not been acknowledged."""
    return await _filter_incidents(
        store,
        lambda fields: (
            fields.get("acknowledged") == "False"
            and (node_id is None or fields.get("node_id") == node_id)
        ),
        include_hosts=include_hosts,
    )


async def get_acknowledged_incidents(
    store: RedisStore,
    *,
    include_hosts: bool = True,
    node_id: str | None = None,
) -> list[dict[str, Any]]:
    """Return incidents that have been acknowledged."""
    return await _filter_incidents(
        store,
        lambda fields: (
            fields.get("acknowledged") == "True"
            and (node_id is None or fields.get("node_id") == node_id)
        ),
        include_hosts=include_hosts,
    )


async def clear_incidents(store: RedisStore) -> int:
    """Delete every incident hash and the index, returning how many were removed."""
    keys = await store.zrangebyscore(KEY_INCIDENTS, "-inf", "+inf")
    removed = 0
    for key in keys:
        removed += 1 if await store.delete(key) else 0
    await store.delete(KEY_INCIDENTS)
    return removed


async def write_log(store: RedisStore, line: str, *, max_entries: int = MAX_LOG_ENTRIES) -> None:
    """Append a log line to the bounded console log list."""
    await store.lpush_trim(KEY_LOGS, line, max_entries=max_entries)


async def get_logs(store: RedisStore, *, limit: int | None = None) -> list[str]:
    """Return recent log lines, newest first."""
    end = -1 if limit is None else max(0, limit - 1)
    return await store.lrange(KEY_LOGS, 0, end)


async def get_console_setting(
    store: RedisStore, setting: str, default: str | None = None
) -> str | None:
    """Read a console setting."""
    value = await store.get_value(f"{KEY_CONSOLE_SETTING_PREFIX}{setting}")
    return default if value is None else value


async def set_console_setting(store: RedisStore, setting: str, value: str) -> None:
    """Write a console setting."""
    await store.set_value(f"{KEY_CONSOLE_SETTING_PREFIX}{setting}", value)


async def should_notify(store: RedisStore, node_id: str) -> bool:
    """Return False when the device opted out of general notifications."""
    value = await store.hget(device_key(node_id), "ignore_notifications_general")
    return value != "True"


async def get_device(store: RedisStore, node_id: str) -> dict[str, Any] | None:
    """Return the device hash plus its unacknowledged incidents."""
    host = await store.hgetall(device_key(node_id))
    if not host:
        return None
    unacknowledged = await get_unacknowledged_incidents(store, include_hosts=False, node_id=node_id)
    return {**host, "unacknowleged_incidents": unacknowledged}


__all__ = [
    "MAX_LOG_ENTRIES",
    "clear_incidents",
    "get_acknowledged_incidents",
    "get_all_incidents",
    "get_console_setting",
    "get_device",
    "get_incident",
    "get_logs",
    "get_unacknowledged_incidents",
    "set_console_setting",
    "should_notify",
    "write_log",
]
