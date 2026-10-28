"""Rule for HTTP requests that reach a canary web service.

OpenCanary logs a plain `GET` as `3000`, an unsupported method as `3002` and a
redirect as `3003`. Without a rule each of them was audited as `event_unrouted`
and then dropped, even though a request to a canary web service is exactly the
signal the operator wants. All three describe the same thing — someone probed
the HTTP service — so they share one incident type and one alert class; login
attempts keep their own `http.login_attempt` (3001), whose message carries
credentials and therefore renders differently.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Final

from opencanary_correlator.constants import LogType
from opencanary_correlator.core.incident import Incident, IncidentRepository
from opencanary_correlator.core.rules.base import Rule
from opencanary_correlator.schemas import CanaryEvent

#: Incident name; the Redis key prefix lives in `constants.INCIDENT_KEY_PREFIX`.
INCIDENT_HTTP_REQUEST: Final[str] = "http.request"

#: Log types that count as a request to the canary HTTP service.
HTTP_REQUEST_LOGTYPES: Final[frozenset[int]] = frozenset(
    {
        int(LogType.LOG_HTTP_GET),
        int(LogType.LOG_HTTP_UNIMPLEMENTED_METHOD),
        int(LogType.LOG_HTTP_REDIRECT),
    }
)


@dataclass(frozen=True, slots=True)
class HttpRequestRule(Rule):
    """Create (or merge) an `http.request` incident for a canary HTTP request."""

    repository: IncidentRepository

    name: ClassVar[str] = "http"

    def matches(self, event: CanaryEvent) -> bool:
        """True for GET, unsupported-method and redirect events."""
        return int(event.logtype) in HTTP_REQUEST_LOGTYPES

    async def apply(self, event: CanaryEvent, *, now: float) -> list[Incident]:
        """Record the request, notifying only when a new incident is created.

        Merging inside `OCC_INCIDENT_HORIZON` keeps a scanner that sends
        hundreds of requests to one alert per source host per window.
        """
        incident = await self.repository.record(INCIDENT_HTTP_REQUEST, event)
        return [incident] if incident is not None else []


__all__ = ["HTTP_REQUEST_LOGTYPES", "INCIDENT_HTTP_REQUEST", "HttpRequestRule"]
