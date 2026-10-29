"""Suppression slots for service messages.

A degraded dependency fails on *every* alert: a rejected VirusTotal key returns
401 for each lookup, a broken GeoIP database raises for every address. Reporting
each failure would replace an alert channel with a stream of the same sentence,
so one slot per `(kind, subject)` admits a message and counts the ones it turned
away, and the counter is handed over with the next admitted message.
"""

from __future__ import annotations

from opencanary_correlator.storage._base import _StoreBase
from opencanary_correlator.storage.keys import service_message_keys


class _ServiceMixin(_StoreBase):
    """Admit one service message per cooldown."""

    async def claim_service_message(
        self, *, kind: str, subject: str, cooldown: float
    ) -> tuple[bool, int]:
        """Return `(admitted, repeats_since_last_message)`.

        `admitted` is False while the cooldown is running; `repeats` is the
        number of occurrences that were suppressed since the previous admitted
        message, so the one that gets through can say how often it happened.
        """
        mute_key, repeat_key = service_message_keys(kind, subject)
        reply = await self._run_script(
            self._service_message_script,
            [mute_key, repeat_key],
            [str(max(1, int(cooldown)))],
        )
        admitted, repeats = (self._text(part) for part in reply)
        return admitted == "1", int(repeats)
