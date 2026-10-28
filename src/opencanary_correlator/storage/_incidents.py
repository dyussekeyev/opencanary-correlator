"""Incident persistence, the index pointer and the bounded lookup scan."""

from __future__ import annotations

from collections.abc import Mapping

from opencanary_correlator.constants import KEY_INCIDENTS
from opencanary_correlator.storage._base import IncidentLookup, _StoreBase


class _IncidentsMixin(_StoreBase):
    """The incident hash, its index entry and the per-host pointer."""

    async def find_recent_incident(
        self,
        prefix: str,
        *,
        min_score: float,
        pointer_key: str | None = None,
        scan_limit: int | None = None,
    ) -> IncidentLookup:
        """Find the newest incident key starting with `prefix` inside the horizon.

        `pointer_key` is the O(1) shortcut: a small hash holding the incident
        :meth:`save_incident` last wrote for this prefix and its score. A missing
        pointer (an incident created by an older replica, or one whose TTL
        expired) and an outdated score both fall back to the authoritative ZSET
        scan, so the legacy index stays the source of truth during a rolling
        upgrade.

        That fallback reads the index newest-first and stops at the first prefix
        match, but without a cap it transferred every incident in the window:
        measured at 1.4 ms with 200 live incidents and 5.5 ms with 2 000, which
        made ingestion O(index size). `scan_limit` bounds the reply to the newest
        N members; since members are ordered by score, a match inside the cap is
        still the newest one for this prefix. A miss is reported as
        ``truncated`` instead of being silently trusted.
        """
        if pointer_key is not None:
            pointer = await self.hgetall(pointer_key)
            pointed = pointer.get("key")
            if pointed is not None and pointed.startswith(prefix):
                try:
                    pointer_score = float(pointer.get("score", ""))
                except ValueError:
                    pointer_score = float("-inf")
                if pointer_score >= min_score:
                    return IncidentLookup(key=pointed)

        candidates = await self.zrevrangebyscore(KEY_INCIDENTS, "+inf", min_score, limit=scan_limit)
        for inspected, key in enumerate(candidates, start=1):
            if key.startswith(prefix):
                return IncidentLookup(key=key, scanned=inspected)
        return IncidentLookup(
            scanned=len(candidates),
            truncated=scan_limit is not None and len(candidates) >= scan_limit,
        )

    async def save_incident(
        self,
        key: str,
        fields: Mapping[str, str],
        *,
        score: float,
        pointer_key: str | None = None,
    ) -> None:
        """Persist the incident hash and refresh its score in the index ZSET.

        The hash, the index and the optional per-host `pointer_key` are written
        by one Lua script, so they are atomic and cost a single round trip.
        The script holds several keys, which requires them to live on the same
        server: Redis Cluster would reject it with ``CROSSSLOT``, and the
        deployment contract is a single logical Redis.
        """
        keys = [key, KEY_INCIDENTS] + ([pointer_key] if pointer_key is not None else [])
        pairs: list[str] = []
        for field, value in fields.items():
            pairs.append(field)
            pairs.append(value)
        await self._run_script(
            self._save_incident_script,
            keys,
            [str(score), key, *pairs],
        )


__all__ = ["_IncidentsMixin"]
