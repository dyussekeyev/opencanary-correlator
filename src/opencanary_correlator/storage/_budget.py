"""The alert budget counters and the summaries of what they withheld.

The budget is a fixed window, held in Redis so every replica shares it: two
correlators behind a load balancer must not each allow twenty notifications per
node. A refusal is counted in the same script as the reservation, so a
suppressed alert cannot be lost between "may I notify?" and "then remember that
I did not".
"""

from __future__ import annotations

from opencanary_correlator.storage._base import _StoreBase
from opencanary_correlator.storage.keys import (
    BUDGET_SUMMARIES,
    budget_global_key,
    budget_node_key,
    budget_summary_key,
)


class _BudgetMixin(_StoreBase):
    """Reserve notifications and collect what a closed window withheld."""

    async def reserve_alert_slot(
        self,
        *,
        node_id: str,
        stamp: int,
        per_node: int,
        global_limit: int,
        window: float,
        summary_due: float,
    ) -> bool:
        """Return True when one notification fits, counting it; False otherwise.

        A refusal is recorded for the window's summary in the same round trip,
        so a suppressed alert is never invisible: it is counted here and the
        count is delivered when the window closes.
        """
        # Two windows of retention: the counters are useless once the window has
        # rolled over, but the summary is read shortly after it closes.
        ttl_ms = max(60_000, int(window * 2000))
        reserved = await self._run_script(
            self._reserve_budget_script,
            [
                budget_node_key(stamp, node_id),
                budget_global_key(stamp),
                budget_summary_key(stamp),
                BUDGET_SUMMARIES,
            ],
            [
                str(per_node),
                str(global_limit),
                str(ttl_ms),
                node_id,
                str(float(summary_due)),
            ],
        )
        return bool(int(reserved or 0))

    async def due_budget_summaries(self, *, now: float, limit: int) -> list[str]:
        """Summaries whose window closed at or before `now`, oldest first."""
        entries = await self._client.zrangebyscore(
            BUDGET_SUMMARIES, "-inf", float(now), start=0, num=max(1, int(limit))
        )
        return [self._text(entry) for entry in entries]

    async def take_budget_summary(self, summary_key: str) -> dict[str, int] | None:
        """Claim one summary for delivery, returning suppressed counts by node.

        Returns None when another replica claimed it first: the removal happens
        inside the script, so exactly one caller sees the counts.
        """
        flat = await self._run_script(
            self._take_budget_summary_script,
            [BUDGET_SUMMARIES, summary_key],
            [summary_key],
        )
        if not flat:
            return None
        values = [self._text(item) for item in flat]
        counts: dict[str, int] = {}
        for name, value in zip(values[0::2], values[1::2], strict=False):
            try:
                counts[name] = int(value)
            except ValueError:
                continue
        return counts or None


__all__ = ["_BudgetMixin"]
