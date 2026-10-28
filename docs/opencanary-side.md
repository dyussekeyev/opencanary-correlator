# Canary-side problems and fixes

Some issues reported against this deployment live in `opencanaryd` itself, not in
the correlator. This page covers what the correlator can and cannot do about
them, and the patch or workaround to apply on the honeypot.

Nothing here is shipped by this package: `opencanary` is a separate project, so
these are operator-side changes.

## 1. `SocketJSONHandler` does not reconnect after the correlator restarts

**Symptom.** Restart the correlator and events stop arriving until `opencanaryd`
is restarted too. The first event after the restart is lost without a message in
either log.

**Why the correlator cannot fix it.** Intake is one-way: the node opens the TCP
connection, the correlator reads from it. When the process restarts, the node's
socket is gone; only the node can open a new one. Nothing the correlator sends
back would be read by `logging.handlers.SocketHandler`.

**Why the record disappears.** `SocketHandler.send()` catches `OSError`, closes
its socket and returns — the record is dropped, the error is never logged. Worse,
a socket that received `FIN` still accepts one more `sendall()`, so the first
write after a restart usually succeeds locally and vanishes on the wire.

**Patch (honeypot side).** Subclass the handler and check the socket before each
write. `select()` reporting readability on an idle socket means the peer sent
`FIN`, so reconnect first, then write. If the correlator is down, retry with a
short delay and report the drop instead of swallowing it.

```python
import logging
import logging.handlers
import select
import socket
import sys
import time


class ReconnectingSocketHandler(logging.handlers.SocketHandler):
    """SocketHandler that reopens a dropped connection instead of losing it."""

    def __init__(self, host, port, *, attempts=4, delay=0.5):
        super().__init__(host, port)
        self.attempts = attempts
        self.delay = delay

    def emit(self, record):
        payload = self.makePickle(record)
        for attempt in range(1, self.attempts + 1):
            try:
                self._send(payload)
                return
            except OSError as exc:
                self.close()
                if attempt == self.attempts:
                    if logging.raiseExceptions:
                        print(
                            f"opencanary: could not reach {self.address[0]}:{self.address[1]} "
                            f"({exc}); record dropped",
                            file=sys.stderr,
                        )
                    return
                time.sleep(self.delay)

    def _send(self, payload):
        # A readable socket with nothing to read is a FIN from the peer: the
        # next sendall() would "succeed" and lose the record on the wire.
        if self.sock is not None and select.select([self.sock], [], [self.sock], 0)[0]:
            self.close()
        if self.sock is None:
            self.createSocket()
            if self.sock is None:  # createSocket reports failure by returning None
                raise OSError("could not connect to the correlator")
        self.sock.sendall(payload)


class ReconnectingSocketJSONHandler(ReconnectingSocketHandler):
    """`opencanary.logger.SocketJSONHandler` framing: one JSON line per record."""

    def makePickle(self, record):  # noqa: N802 - stdlib API
        return record.getMessage().encode("utf-8") + b"\n"
```

Point the canary's `logger` configuration at `ReconnectingSocketJSONHandler`
instead of `opencanary.logger.SocketJSONHandler`. If the stock handler overrides
`makePickle`, inherit from it (`class ...(ReconnectingMixin, SocketJSONHandler)`)
so the wire format stays byte-identical.

Verified locally against a TCP sink that accepts one line and then closes the
connection: the record written before the close arrives, the record written
immediately after it arrives on a fresh connection, and a record written while
nothing listens is retried four times (~2 s) and then reported on stderr instead
of disappearing. Residual risk: a `FIN` that has not reached the node yet
(restart on a heavily loaded link) still loses that one record — the kernel has
no way to know the peer is gone until it tries to write and gets an `RST`.

**What the correlator does about it.** It cannot force a reconnect, but it now
records the moment a canary goes silent: when the node closes the connection, the
audit trail gets

```json
{"component": "correlator", "action": "connection_closed", "status": "info",
 "details": {"receiver": "tcp_json", "reason": "peer_closed", "peer": "10.0.0.9"}}
```

so a gap in `event_*` records for that peer can be tied to a real disconnect
instead of being inferred. Alert on `opencanary_active_connections` dropping to
zero if you want a notification.

## 2. `twistd.pid` is not cleaned when the container restarts

**Symptom.** `opencanary` started with `twistd --pidfile=/var/run/twistd.pid`
inside a container refuses to start after a restart: the PID file survived the
container (a mounted path or a layer written by the previous process) and
`twistd` exits with "PID file already exists".

**Fixes, in order of preference** (all on the canary image):

```dockerfile
# 1. Do not write the PID file at all.
CMD ["twistd", "--pidfile=/dev/null", "--nodaemon", "opencanaryd", ...]
```

```dockerfile
# 2. Keep the file but put it on a tmpfs-backed path so it cannot survive.
CMD ["twistd", "--pidfile=/tmp/twistd.pid", "--nodaemon", "opencanaryd", ...]
```

```sh
# 3. Clean it in the entrypoint, before twistd starts.
#!/bin/sh
rm -f /var/run/twistd.pid
exec "$@"
```

A compose-level override (mounting `/var/run` as `tmpfs`, or an `entrypoint` that
removes the file) works too, but it has to be repeated on every deployment that
starts the image; the three options above fix the image itself, which is why they
are listed first.
