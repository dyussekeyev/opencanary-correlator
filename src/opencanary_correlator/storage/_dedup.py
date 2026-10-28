"""Event deduplication: one fingerprint, one claim, one window.

The claim is a **lease**, not a window: it is written before the rules run with a
short TTL, so a process that dies mid-correlation cannot suppress the
redelivery the canary makes after it reconnects. Only a claim that produced a
decision is extended to the full `OCC_DEDUP_TTL`.

Both transitions compare the token, so a replica can never extend or delete a
claim the lease already handed to somebody else.
"""

from __future__ import annotations

from opencanary_correlator.storage._base import _StoreBase
from opencanary_correlator.storage.keys import dedup_key


class _DedupMixin(_StoreBase):
    """First writer wins until the lease runs out, then until the window does."""

    async def acquire_dedup(self, fingerprint: str, *, ttl: float, token: str) -> bool:
        """Take the claim for `ttl` seconds, if nobody else holds it."""
        return bool(
            await self._client.set(
                dedup_key(fingerprint),
                token,
                nx=True,
                px=max(1, int(ttl * 1000)),
            )
        )

    async def confirm_dedup(self, fingerprint: str, *, ttl: float, token: str) -> bool:
        """Extend our claim to the full dedup window, returning whether we own it.

        False means the lease expired while the rules ran and another delivery
        may hold the claim now: the event was still correlated, so this is a
        signal to watch, not an error.
        """
        extended = await self._run_script(
            self._confirm_dedup_script,
            [dedup_key(fingerprint)],
            [token, str(max(1, int(ttl * 1000)))],
        )
        return bool(extended)

    async def release_dedup(self, fingerprint: str, *, token: str) -> bool:
        """Withdraw a claim that produced no correlation, if it is still ours.

        A rule failure happens after the claim is taken, and keeping it would
        swallow a redelivery of an event that never reached the store.
        """
        released = await self._run_script(
            self._release_lock_script, [dedup_key(fingerprint)], [token]
        )
        return bool(released)


__all__ = ["_DedupMixin"]
