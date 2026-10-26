"""TCP receiver for OpenCanary's ``SocketJSONHandler``.

`opencanary.logger.SocketJSONHandler.makePickle()` returns
``record.getMessage() + "\\n"``, where the message is the JSON document produced
by ``LoggerBase.sanitizeLog()``. This receiver consumes exactly that stream: no
length prefix, no pickle, no handshake, and no changes on the honeypot side.
"""

from __future__ import annotations

import json
from typing import NoReturn

from pydantic import ValidationError

from opencanary_correlator.connectors.receivers._pipeline import schema_error_details
from opencanary_correlator.connectors.receivers._tcp import StreamProtocol, TCPStreamReceiver
from opencanary_correlator.schemas import CanaryEvent

CANARY_ERROR_PREFIX = "[ERR] "


def _reject_json_constant(value: str) -> NoReturn:
    """Reject NaN/Infinity, which Python's json module accepts by default."""
    raise ValueError(f"non-finite JSON constant: {value}")


class TCPJSONProtocol(StreamProtocol):
    """Newline-framed JSON connection."""


class TCPJSONReceiver(TCPStreamReceiver):
    """Receive OpenCanary events over TCP as newline-delimited JSON."""

    name = "tcp_json"

    def _protocol_factory(self) -> StreamProtocol:
        return TCPJSONProtocol(self)

    def parse_payload(self, payload: bytes, peer_ip: str) -> CanaryEvent | None:
        """Validate one JSON line, auditing and skipping anything malformed."""
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError:
            self.audit_rejection("invalid_utf8", peer_ip)
            return None

        text = text.strip()
        if not text:
            return None

        # `PyLogger.error()` emits "[ERR] '…'" instead of JSON. Canaries send it
        # on internal failures, so it must be tolerated, not treated as fatal.
        if text.startswith(CANARY_ERROR_PREFIX):
            self.audit_rejection("canary_error_line", peer_ip)
            return None

        try:
            raw = json.loads(text, parse_constant=_reject_json_constant)
        except (json.JSONDecodeError, ValueError) as exc:
            self.audit_rejection(
                "malformed_json",
                peer_ip,
                error_type=type(exc).__name__,
                position=getattr(exc, "pos", None),
            )
            return None

        if not isinstance(raw, dict):
            self.audit_rejection("non_object_payload", peer_ip, payload_type=type(raw).__name__)
            return None

        try:
            return CanaryEvent.model_validate(raw)
        except ValidationError as exc:
            self.audit_rejection("schema_validation", peer_ip, **schema_error_details(exc))
            return None


__all__ = ["CANARY_ERROR_PREFIX", "TCPJSONProtocol", "TCPJSONReceiver"]
