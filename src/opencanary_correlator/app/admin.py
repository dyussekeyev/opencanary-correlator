"""Operator commands that run instead of the correlator.

They exist because the two recoverable failure modes need a human decision: a
delivery buried in the dead letter list is inspected, then replayed on purpose,
and expired state is removed only when retention was enabled. Both paths are
bounded and audited; nothing here deletes a delivery that is still owed.
"""

from __future__ import annotations

import json
import sys
import time

from opencanary_correlator.audit import AuditLogger
from opencanary_correlator.config import Settings
from opencanary_correlator.core.retention import RetentionJanitor
from opencanary_correlator.storage.redis_store import RedisStore


async def run_admin(
    settings: Settings,
    *,
    dlq_list: int | None = None,
    dlq_replay: str | None = None,
    retention_run: bool = False,
) -> int:
    """Run one administrative action and return the process exit code."""
    store = RedisStore.from_url(settings.redis_url)
    # The audit stream goes to stderr so stdout stays parseable by a script.
    audit = AuditLogger("cli", stream=sys.stderr)
    try:
        if not await store.ping():
            print("Redis is not reachable", file=sys.stderr)
            return 1
        if retention_run:
            if not settings.retention_enabled:
                print(
                    "retention is disabled; set OCC_RETENTION_ENABLED=true to allow deletion",
                    file=sys.stderr,
                )
                return 2
            summary = await RetentionJanitor(store, settings, audit).run_once()
            print(json.dumps(summary, sort_keys=True))
            return 0
        if dlq_replay is not None:
            replayed = await store.replay_dead_letter(
                dlq_replay, now=time.time(), retention=settings.outbox_delivery_retention
            )
            if not replayed:
                print(f"no dead letter named {dlq_replay}", file=sys.stderr)
                return 1
            audit.emit("dlq_replayed", "info", {"entry": dlq_replay})
            print(json.dumps({"entry": dlq_replay, "replayed": True}, sort_keys=True))
            return 0
        for entry in await store.dead_letters(limit=dlq_list or 20):
            print(json.dumps(entry, sort_keys=True))
        return 0
    finally:
        await store.aclose()


__all__ = ["run_admin"]
