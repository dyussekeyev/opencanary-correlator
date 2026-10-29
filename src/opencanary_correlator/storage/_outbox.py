"""The alert outbox: deliveries that survive the process that decided on them.

An incident is written and its pending deliveries are enqueued in one script
(:meth:`save_new_incident`), so the decision to notify cannot exist without a
record of it. The entry is then removed only after a channel accepted the
message, which is what turns delivery from best-effort into at-least-once.

The index is a ZSET scored by the next attempt, so a retry is a score change
rather than a second entry, and claiming pushes the score forward by a lease:
a worker that dies mid-delivery leaves the entry to become due again instead of
losing it.
"""

from __future__ import annotations

from collections.abc import Sequence

from opencanary_correlator.storage._base import _StoreBase
from opencanary_correlator.storage.keys import (
    OUTBOX_DEAD,
    OUTBOX_INDEX,
    delivered_key,
    outbox_alert_key,
)


class _OutboxMixin(_StoreBase):
    """Enqueue, claim, settle and bury alert deliveries."""

    async def enqueue_alert(
        self,
        entry_id: str,
        *,
        incident_key: str,
        channel: str,
        score: float,
    ) -> None:
        """Add one pending delivery, usually only from a test or a repair tool."""
        async with self._client.pipeline(transaction=True) as pipe:
            pipe.hset(
                outbox_alert_key(entry_id),
                mapping={
                    "incident": incident_key,
                    "channel": channel,
                    "attempts": "0",
                    "created": str(score),
                },
            )
            pipe.zadd(OUTBOX_INDEX, {entry_id: score})
            await pipe.execute()

    async def discard_alerts(self, entry_ids: Sequence[str]) -> int:
        """Drop pending deliveries in one script, returning how many existed.

        Used when the decision to notify is withdrawn before any attempt: the
        alert budget suppresses a notification, and a surviving entry would only
        delay the message the ration was meant to withhold.
        """
        if not entry_ids:
            return 0
        removed = await self._run_script(
            self._discard_alerts_script,
            [OUTBOX_INDEX, *(outbox_alert_key(entry_id) for entry_id in entry_ids)],
            list(entry_ids),
        )
        return int(removed or 0)

    async def claim_due_alerts(self, *, now: float, limit: int, lease: float) -> list[str]:
        """Return the ids that are due, pushing each one's next attempt by `lease`."""
        claimed = await self._run_script(
            self._claim_alerts_script,
            [OUTBOX_INDEX],
            [str(now), str(max(1, int(limit))), str(max(0.0, lease))],
        )
        return [self._text(entry) for entry in claimed or []]

    async def read_alert(self, entry_id: str) -> dict[str, str] | None:
        """Read one pending delivery, or None when it is gone."""
        fields = await self.hgetall(outbox_alert_key(entry_id))
        return fields or None

    async def settle_alert(self, entry_id: str, *, retention: float) -> bool:
        """Mark one delivery as done and drop its entry.

        Returns False when the entry no longer exists: another replica settled
        it, or it was never enqueued (an incident created by a build without an
        outbox). Both are normal and neither is an error.
        """
        settled = await self._run_script(
            self._settle_alert_script,
            [outbox_alert_key(entry_id), delivered_key(entry_id), OUTBOX_INDEX],
            [entry_id, str(max(1, int(retention)))],
        )
        return bool(settled)

    async def reschedule_alert(
        self,
        entry_id: str,
        *,
        attempts: int,
        error: str,
        next_attempt: float,
        retention: float,
    ) -> None:
        """Record a failed attempt and make the entry due again later."""
        key = outbox_alert_key(entry_id)
        if not await self.exists(key):
            return
        async with self._client.pipeline(transaction=True) as pipe:
            pipe.hset(key, mapping={"attempts": str(attempts), "last_error": error[:200]})
            pipe.expire(key, max(1, int(retention)))
            pipe.zadd(OUTBOX_INDEX, {entry_id: next_attempt})
            await pipe.execute()

    async def bury_alert(self, entry_id: str, *, attempts: int, error: str) -> None:
        """Move an exhausted delivery to the dead letter list for inspection."""
        key = outbox_alert_key(entry_id)
        async with self._client.pipeline(transaction=True) as pipe:
            pipe.hset(
                key,
                mapping={
                    "attempts": str(attempts),
                    "last_error": error[:200],
                    "state": "dead",
                },
            )
            pipe.zadd(OUTBOX_DEAD, {entry_id: attempts})
            pipe.zrem(OUTBOX_INDEX, entry_id)
            await pipe.execute()

    async def outbox_pending(self) -> int:
        """Number of deliveries waiting for a worker."""
        return int(await self._client.zcard(OUTBOX_INDEX))

    async def outbox_dead(self) -> int:
        """Number of deliveries that exhausted their attempts."""
        return int(await self._client.zcard(OUTBOX_DEAD))


__all__ = ["_OutboxMixin"]
