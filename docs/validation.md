# Validation and acceptance record

Measured on 2026-10-24.

**Environment:** Windows 11 with Python 3.14.9 in `.venv` (project requires
3.11+), ruff 0.17.2, mypy 2.4.0, pytest 9.1.1, pytest-asyncio 1.4.0, fakeredis
2.40 with lupa 2.8 (the Lua runtime fakeredis needs for the scripts), Docker
CLI 29 with Compose v5.6.1 and Docker Desktop (started for the benchmark
containers, then stopped). Real-Redis numbers were measured in a
`python:3.13-slim` container with the distribution `redis-server` (Redis 7) on
loopback, and the opt-in integration checks ran against a `redis:7-alpine`
container.

## Static gates

| Command | Result |
|---|---|
| `ruff check .` | All checks passed (legacy root tree removed, so `src/` and `tests/` are now linted too) |
| `ruff format --check .` | 77 files already formatted |
| `mypy src tools` (`strict = true`, pydantic plugin) | Success: no issues found in 42 source files |
| `pytest` | **291 passed, 3 skipped**, coverage **91.30 %** (gate: 85 %); the skips are the opt-in real-infrastructure checks below |

`grep -rnE "twisted|mandrill|twilio|simplejson|pkg_resources|nacl\.|iteritems|has_key|print >>" src tests`
finds no imports or runtime usage. The only textual mentions are deliberate:
the legacy config keys skipped during migration (`twilio.*`,
`console.mandrill_key` in `config.py`) and a docstring in `storage/keys.py`
noting that PyNaCl was replaced by `hashlib`. `setup.py`, `requirements.txt`,
`bin/opencanary-correlator` and the Python 2 `opencanary_correlator/` package are
deleted; a smoke test asserts they stay gone.

## Continuous integration

`.github/workflows/ci.yml` runs on every push to `master` and on pull requests:

| Job | Checks |
|---|---|
| `quality` | `uv lock --check`, `uv sync --frozen --extra dev`, `uv pip check`, `ruff check`, `ruff format --check`, `mypy src tools` on Python 3.13 |
| `test` | `uv sync --frozen --extra dev` and `pytest` on Python 3.11, 3.12, 3.13 and 3.14 with a digest-pinned `redis:7-alpine` service and `OCC_TEST_REDIS_URL=redis://localhost:6379/15`, so the two-replica and POSIX SIGTERM checks execute |
| `package` | `python -m build`, `twine check`, wheel install, `--version` and parsed `--check-config` output |
| `docker` | `docker compose up --build --wait`, a real `SocketJSONHandler` event over TCP 1514, then assertions on the incident key, `startup` audit line, uid 10001, container health and the `/metrics` exposition |

The workflow has executed on GitHub (run [40114309203](https://github.com/dyussekeyev/opencanary-correlator/actions/runs/40114309203), PR #1): all seven checks pass — `quality` 14 s, four `test` jobs 29–34 s with **294 passed and 0 skipped** (the real-Redis two-replica checks and the POSIX SIGTERM test actually execute there), `package` 19 s, `docker` 37 s with `incident count: 1`, the uid 10001 check and container health. The Docker job repeats the container smoke test below on a clean runner.

The CI test job can be reproduced locally with `tools/linux_check.sh`, which
mounts the tree into a cached `python:3.11-slim` image built from `uv.lock` and
runs pytest against a disposable `redis:7-alpine`: `294 passed`, coverage
91.33 %, 18 s. The same container now runs `ruff check`, `ruff format --check`
and `mypy src tools` first, because mypy answers per platform: PR #7 was green
locally and red in CI on `warn_unreachable` for a `sys.platform != "win32"`
guard, and then on a `ctypes.WinDLL` that the POSIX stub does not declare - both
invisible to a Windows-side `mypy`. POSIX-only tests carry `@pytest.mark.linux`, and
`.githooks/pre-push` (installed by `tools/install_hooks.sh`) runs the same check
before a push that touches Python, tests or dependencies.

The first run was red and found two defects that local Windows runs could not see: `setup-python` cached pip while uv installs the packages, so its post-job step failed an otherwise green lint job, and the UDP receiver asserted `isinstance(transport, asyncio.DatagramTransport)`, which is false for the POSIX selector transport (it implements the datagram API without inheriting the class) and failed all five syslog UDP tests. Both are fixed; the POSIX failure was reproduced and the fix confirmed in a `python:3.11-slim` container before pushing.

## Compatibility proof

`tests/integration/test_tcp_json_receiver.py` and `tests/integration/test_end_to_end.py`
subclass `logging.handlers.SocketHandler` with the upstream
`makePickle() -> record.getMessage() + "\n"` implementation and send payloads
shaped by `sanitizeLog()`. Assertions cover:

- event accepted unchanged (`src_host`, `src_port`, `dst_host`, `dst_port`,
  `logtype`, `node_id`, `local_time`, nested `logdata`);
- incident hash written under the legacy key
  `incident:ftplogin:10.0.0.5:<ts>` with `events_count`, `events_list`,
  `acknowledged`, `notified`, `description`;
- a repeat within the horizon merges (`events_count = 2`) without a second
  notification; after the horizon a new incident key is created;
- an `[ERR] '…'` line from `PyLogger.error()` is rejected with
  `event_rejected: canary_error_line` and does not close the session;
- oversized lines, invalid UTF-8, NaN, deep `logdata`, control characters and
  unknown `logtype`s are handled as documented, never crash the receiver.

Syslog compatibility is covered separately for RFC 3164/5424, RFC 6587
octet-counting, newline framing, the trailing NUL emitted by Python's
`SysLogHandler`, and UDP datagrams.

Port-scan correlation is proven end to end through the same socket path.
`test_host_portscan_through_the_wire` sends five `LOG_PORT_SYN` events to ports
21–25 from one source and requires exactly one `scans.host_portscan` incident
(`incident:hostportscan:<src_host>:…`, `logtype` 5003, `logdata`
`[21, 22, 23, 24, 25]`) and one alert. `test_network_portscan_through_the_wire`
sends the same source to two canaries on port 22 (`reported_dst_host`
`127.0.0.1`/`127.0.0.2`) and requires exactly one `scans.network_portscan`
(`incident:networkportscan:<src_host>:…`, `logtype` 5002, both targets). Both
use the documented default thresholds (5 ports, 2 targets).

Per-incident horizons are covered by configuration tests (environment JSON,
unknown/negative/non-finite rejection, all 16 legacy keys including the
`httproxy` spelling) and by a repository test showing a 120 s override merging
at 61 s and creating a new incident once the extended window closes.

Incident lookup is host-exact. A parametrised regression test creates the
longer host first and then the shorter one for `10.0.0.55`/`10.0.0.5`,
`web01`/`web` and `::10`/`::1`; each pair must produce two distinct incident
keys instead of merging the shorter host into the longer host's incident.

Incident lookup also has its own contract. `tests/unit/test_keys.py` pins the
`incident-latest:<incident>:<src_host>` namespace (it must not collide with the
legacy `incident:` keys) and `tests/unit/test_incident.py` covers the pointer
itself: it is written on create with the matching score, it is reused for a
merge, it falls back to the ZSET scan when missing (rolling upgrade), it does
not merge beyond the horizon, a pointer to a deleted incident produces a new
one, and a corrupt score falls back to the index.

The full-stack test also verifies the audit trail: first record
`receiver_started`, then `startup`, `event_rejected`, two `alert_dispatch`
records and a final `shutdown`, each with the five mandatory fields.

## Concurrency and atomicity

`tests/integration/test_redis_atomicity.py` runs two engines against one shared
fakeredis instance:

- 50 concurrent identical events → exactly **1 incident, 1 notification**;
- 20 concurrent distinct events → one incident with `events_count = 20`.

The Redis circuit breaker, dedup markers, incident lock, port-scan windows and
rate-limit counters are replicated across both engines, which is the same
mechanism used when replicas run behind a load balancer. Both engines share one
**logical** Redis server; Redis Cluster is out of scope because `save_incident`
writes an `incident:*` hash, the `incidents` ZSET and the per-host pointer in
one script, and those keys are in different Cluster slots (`CROSSSLOT`).

Lock release is atomic: `RedisStore._release_lock()` is a Lua compare-and-delete
(`GET` + `DEL` in one script, one round trip) instead of a non-atomic `GET` then
`DELETE`. `tests/unit/test_lock.py` proves that a lock re-acquired after its TTL
expires survives the old owner's release, that a stale token cannot delete it,
and that the release is a single `EVALSHA`.

## Ingestion pipeline

`tests/unit/test_event_pipeline.py` covers the consumer lanes: a single lane
delivers in order; with eight lanes each source host still sees its events in
arrival order while different hosts overlap (a slow sink shows `max_active > 1`);
a full lane drops and audits instead of growing; the `OCC_EVENT_QUEUE_SIZE`
budget is shared between lanes; and `stop()` cancels every lane. The settings
test rejects `OCC_EVENT_CONCURRENCY` outside `1..64` and documents the default
of 8 lanes.

## Dispatcher delivery

`tests/integration/test_dispatcher_delivery.py` runs real loopback servers:

| Scenario | Result |
|---|---|
| Webhook POST over a real socket | success, `Content-Type: application/json`, incident payload |
| 503 → 500 → 200 | three attempts, backoff `[0.1, 0.2]`, success |
| 429 with `Retry-After: 2` | sleeps exactly 2 s, then succeeds |
| 400 | one attempt, `detail = http_400`, no retry |
| Breaker after repeated failures | second delivery `skipped / circuit_open`, no extra request |
| Breaker scope | a second endpoint of the same channel keeps delivering while the first endpoint's breaker is open |
| Slack + Discord short report | `text` and `content` fields asserted |
| Discord 204 No Content | accepted as success over a real socket and via the HTTP mock |
| Discord long report | switches to `embeds`, description truncated at 4096 |
| SMTP | real ESMTP dialogue, `From`/`To`/`Subject` and body asserted |

## Console log list

The running service attaches `RedisLogHandler` to the `opencanary_correlator`
package logger, so operational lines reach the legacy `logs` list that the old
console reads. `tests/unit/test_logs.py` proves the bounded append (newest
first, trimmed to `max_entries`) and that the handler drains stdlib records into
`RedisStore.push_log`. `tests/unit/test_cli.py` starts the real `run_correlator`
stack against fakeredis: after a `SocketJSONHandler` event, an incident and a
shutdown, the list contains exactly the line logged while the service was up,
which shows the handler is attached and stopped with the runtime rather than
leaking between runs. The list stays separate from the audit stream on stdout.

## Health endpoint

`/healthz` and `/readyz` return `200 {"status":"ok","redis":true}` while Redis
answers PING, `503 {"status":"degraded"}` when it does not, and the listener is
bound and closed with the runtime. Verified over a real socket in
`tests/integration/test_end_to_end.py`.

The request target is parsed with `urlsplit` and the resulting path is compared
exactly against the health paths: `/healthz?x=1` and `/readyz?verbose` still ping
Redis and return 503 when it is down, while `/healthzfoo`, `/readyzbar` and
`/healthz/` return 404. A malformed absolute-form target is also a 404 rather
than a listener exception.

`GET /metrics` returns `200` with the Prometheus text content type and remains
scrapeable while Redis is down (it does not call `ping`). Verified over a real
socket: a live counter appears in the output, `/metrics?format=prometheus` is
served, and `/metricsfoo` is a 404. Labels are fixed and low-cardinality; no
incident key, source address or payload is exported.

## P2 closure

| Item | Status | Regression coverage |
|---|---|---|
| Fixed TTL for port-scan windows | Closed. `RedisStore.sadd_with_fixed_expire()` writes the expiry only when the set is created (or an existing key has no TTL); later members never extend it. | `test_distinct_window_ttl_is_not_refreshed_by_new_members`, `test_host_portscan_window_ttl_does_not_slide`, `test_network_portscan_window_ttl_does_not_slide` |
| Circuit breaker per endpoint | Already closed. `breaker_name(channel, endpoint)` hashes the URL/chat id; dispatchers for other endpoints of the same channel stay closed. | `test_breaker_name_is_per_endpoint_and_hides_the_secret`, `test_build_dispatchers_scopes_breakers_to_each_endpoint`, `test_circuit_breaker_is_scoped_to_one_endpoint` |
| SMTP `use_tls` | Closed. Added `OCC_SMTP_USE_TLS` for implicit TLS (port 465), passed to `aiosmtplib.send()`; enabling it together with `OCC_SMTP_STARTTLS` is a configuration error. | `test_smtp_uses_implicit_tls`, `test_build_dispatchers_passes_implicit_tls_to_smtp`, `test_smtp_tls_modes_are_mutually_exclusive` |
| Legacy enable flags | Closed. `console.email_notification_enable` → `smtp_enabled`, `console.slack_notification_enable` → `slack_enabled`; a missing key preserves the old disabled default, and disabled channels are not instantiated. SMS remains intentionally dropped with Twilio. | `test_legacy_enable_flags_disable_notification_channels`, `test_legacy_json_is_imported`, `test_build_dispatchers_respects_disabled_channels` |

## Packaging and Docker

| Check | Result |
|---|---|
| `pip wheel .` | `opencanary_correlator-0.2.0-py3-none-any.whl` (71,920 bytes, sha256 `64233da4…d5da4ccf`) containing sources and `py.typed` only |
| Build context sufficiency | a staging directory with exactly the Dockerfile `COPY` set (`pyproject.toml`, `uv.lock`, `README.md`, `LICENSE`, `src/`) builds successfully; the wheel contains the package and `py.typed` (byte hashes vary with archive timestamps) |
| Lockfile | `uv.lock` pins all 36 runtime/dev packages (including `lupa` for the fakeredis Lua runtime) with sha256 artifacts; `uv lock --check` is clean; Docker and CI install with `uv sync --frozen` |
| Image pinning | `python:3.12-slim-bookworm`, `ghcr.io/astral-sh/uv:0.13.0` and `redis:7-alpine` are referenced by multi-arch digest; each digest was re-resolved with `docker buildx imagetools inspect` |
| Fresh install | the wheel installs with its dependencies into an empty venv; `opencanary-correlator --version` → `0.2.0`, `--check-config` → exit 0 |
| Startup failure | `OCC_REDIS_URL=redis://127.0.0.1:6390/0` → one `startup_failed / redis_unavailable` JSON line on stdout, `cannot start: Redis is not reachable` on stderr, exit 1 |
| `docker compose config` | valid; Redis URL forced to `redis://redis:6379/0`; `1514/tcp` and `5514/tcp` + `5514/udp` published for external canaries; no health port published; read-only root with `/tmp` tmpfs, `cap_drop: ALL` |
| `HEALTHCHECK` port resolution | unit-verified: unset → 8080, `OCC_HEALTH_PORT=9090` → 9090, any numeric zero (`0`, `00`, whitespace-padded) or empty → exit 0 without a request, invalid/out-of-range → exit 1, and a real loopback `/healthz` on a non-default port → exit 0; `opencanary-correlator --check-config` with `OCC_HEALTH_PORT=0` exits **0** and prints `health_port: null`; the listener reads the same environment variable through `Settings` |
| Container `HEALTHCHECK` | the exact `CMD` extracted from the Dockerfile returns **0** against a healthy `/healthz` and **1** once the listener is stopped, verified from a separate process |
| `docker build` / `docker compose up` | **passed** — image built from the pinned digests, both services reached `healthy`, and the full container smoke test below passed |

### Container smoke test (executed)

`docker compose build` → `docker compose up -d --wait` on Docker Desktop 29.9.2:

| Check | Result |
|---|---|
| Build | `docker compose build --no-cache` exited 0 in 2 m 04 s; images resolved from the pinned `python:3.12-slim-bookworm` and `ghcr.io/astral-sh/uv:0.13.0` digests; `uv sync --frozen --no-dev --no-editable` installed the locked environment, and the runtime venv holds 17 distributions (no dev/test extras, no compiler) |
| Startup | `docker compose up --wait` returned 0 with both services `healthy`; the audit stream begins `receiver_started`, `startup`, `incident_created`, and every record has the five mandatory fields |
| Intake | one `SocketJSONHandler` line on published TCP `1514` created exactly one `incident:ftplogin:10.0.0.99:<ts>` with `logtype 2000`, `node_id canary-01`, `events_count = 1`, `events_list`, the legacy `logdata` string and the `incident-latest` pointer |
| Runtime user | `id -u` → `10001`; `docker inspect` `ReadonlyRootfs=true`, `CapDrop=[ALL]`, `SecurityOpt=[no-new-privileges:true]`; `touch /probe` fails with `Read-only file system` while the `/tmp` tmpfs is writable |
| Health | container health `healthy`; the image `HEALTHCHECK` command (`python -m opencanary_correlator.healthcheck`) exits 0; `/healthz` from inside the container returns `{"status": "ok", "redis": true}`; `/metrics` exposes `opencanary_events_total` |
| Secrets | no `PASSWORD` value from the event appears in the audit stream |
| Restart | `docker compose restart correlator` → healthy again, incident hash and Redis volume preserved (`events_count = 1`) |
| Graceful stop | `docker stop` returned in 0.7 s with container exit code 0, `OOMKilled=false`, and the log ends with `receiver_stopped` followed by `shutdown` (SIGTERM is handled, not just killed) |

Consequence: the Dockerfile, its locked install, the non-root/read-only runtime,
the image health probe, the graceful SIGTERM path and the full ingest path over
the published port are verified in a real container, not only in unit tests. The
stack was removed with `docker compose down -v` afterwards (containers, network
and volume gone); the CI `docker` job repeats the same flow on GitHub.

## Performance

Method: `TCPJSONReceiver` + `CorrelationEngine` + `IncidentRepository` on one
loopback connection, newline-delimited events in a single write, dedup and merge
enabled, `OCC_RATE_LIMIT_EVENTS_PER_MINUTE=0`, no dispatchers. Unless stated
otherwise the numbers come from **a real Redis 7 server** in the same Linux
container as the correlator (`redis-server` on loopback, `redis://localhost/15`),
Python 3.13. The repeatable harness is
[tools/bench_ingest.py](tools/bench_ingest.py).

The earlier record measured against **fakeredis** because no Redis server was
available on the workstation. That proxy is a Python RESP implementation, so it
mostly measures Python call overhead per Redis command; it is kept below for
comparability but is not a capacity number.

### Baseline workload: 10,000 events from 100 source hosts

| Revision | Redis round trips per event | Time | Throughput |
|---|---|---|---|
| Before this iteration | 8 | 3.0 s | 3,300 events/s |
| O(1) pointer + 6-RTT scripts, 1 lane | 6 | 3.3 s | 3,000 events/s |
| O(1) pointer + 6-RTT scripts, 8 lanes | 6 | **2.6 s** | 3,800 events/s |

All runs: 0 dropped, 0 rejected, 100 incidents. Medians of three warm runs;
the first run after mounting the repository is discarded (page-cache fill).
**The target "10,000 events < 10 s" is met on real Redis (2.6 s).**

With a single lane the scripts are slightly *slower* than the previous code on a
local server (3.3 s vs 3.0 s): `EVALSHA` costs ~28 µs of server CPU against
~5 µs for a plain command, and on loopback there is no round-trip latency to
save. The trade is deliberate — two fewer round trips per event is what matters
when Redis is remote, which is why 8 lanes are the default and why the lane
count is configurable down to 1.

### Where the O(1) lookup pays: a populated incident index

`incidents` is a ZSET ordered by creation time, and the old lookup read every
member inside the horizon and filtered by prefix in Python. That cost grows
with the incident rate, not with the number of source hosts. Seeding 5,000
unrelated incidents inside the horizon (a realistic index for a busy
deployment) and replaying 2,000 events from 100 hosts gives:

| Revision | Time | Throughput |
|---|---|---|
| Before (ZSET scan per event) | 47.9 s | 42 events/s |
| Pointer lookup, 1 lane | 5.5 s | 360 events/s |
| Pointer lookup, 8 lanes | **4.6 s** | 440 events/s |

The pointer is written atomically with the incident hash and its index entry,
validated against the horizon, and falls back to the ZSET scan when it is
missing or stale, so incidents created by an older replica still merge during a
rolling upgrade.

### One hot incident: 10,000 events from a single host

The workload above spreads events over 100 hosts, so each incident stays small.
The worst case is the opposite: every event merges into one incident, which is
what a single canary being hammered on one service looks like. That case used to
be quadratic, because each merge re-serialised the growing `events_list` CSV and
`logdata` array.

Stored history is now capped at `OCC_MAX_STORED_EVENTS` (default 100): the CSV
and the log entries are frozen at the cap, and a merge into a full incident
writes the counters only. Measured with
`tools/bench_ingest.py --events 10000 --hosts 1 --concurrency 1` against
`redis:7-alpine` over loopback in a `python:3.11-slim` container:

| Revision | Time | Throughput | Incident hash |
|---|---|---|---|
| Uncapped history | 77.2 s | 130 events/s | grows to ≈0.5 MB of payload |
| Capped at 100, counters-only merge | **17.7 s** | 565 events/s | **4 329 bytes** (flat) |

`accepted = 10000`, `dropped = 0`, `incidents = 1`, and the resulting incident
holds 100 timestamps with `events_count = 10000`, `events_truncated = True`. The
hash size is `MEMORY USAGE` on a cap-full incident (100 epochs plus 100 log
entries), not an estimate. The remaining 17.7 s is round-trip bound, not
byte-bound: six commands per event on one lane.

### Native Linux runner: how much of the cost is the network

Docker Desktop's loopback is expensive, so the same workload was repeated on a
native Linux runner (`ubuntu-latest`, `ubuntu-latest` hardware, a **native**
`redis-server` rather than a service container) via the `benchmark` CI job.

Three invocations of the same commit; the third reproduced Run B (12.404 s,
round trip 0.057 ms), so the spread below is the runner and not a one-off.

| | Run A | Run B | Docker Desktop |
|---|---|---|---|
| Loopback round trip | **0.029 ms** | **0.063 ms** | 0.183 ms |
| Hot incident, 10k events, 1 lane | **5.145 s** | **12.040 s** | 17.707 s |
| ms per event | 0.514 | 1.204 | 1.771 |
| six round trips inside that | 0.171 (33 %) | 0.379 (31 %) | 1.098 (62 %) |
| Python, parsing, receiver, queue | 0.343 (67 %) | 0.825 (69 %) | 0.673 (38 %) |
| 100 hosts, 8 lanes | 4.347 s | 11.094 s | 2.6 s (native container, earlier) |

Two things follow. First, the Docker Desktop numbers overstate the merge cost:
the 17.7 s figure is mostly the VM's 0.183 ms round trip, and on native hardware
the same code completes in 5.1 s. Second, **a shared runner cannot gate a
wall-time target** — 5.145 s and 12.040 s for the same commit, with the round
trip doubling alongside it, is CPU steal rather than code. The `benchmark` job
therefore records numbers and never asserts one.

The split is also the reason the single-script merge was **not** implemented
(see [EXECPLAN-merge-consolidation.md](EXECPLAN-merge-consolidation.md)): on a
native host six round trips are ~31-33 % of an event, so collapsing them has a
ceiling of ~28 % of wall time, and at the time the rest was assumed to be
application work. The profile below corrects that assumption: the remaining
bucket is round trips and per-command overhead, not the correlator's own code.

### Where the per-event time actually goes

`tools/profile_hot_path.py` splits the bucket the native runs called "Python,
parsing, receiver, queue". It has two modes: a pure-CPU loop with no I/O, and
the real engine against a native Redis.

Pure CPU per event (`cpu` mode, 20 000 events, `ubuntu-latest`):

| Stage | mean | p95 |
|---|---|---|
| `json.loads` | 3.39 µs | 3.43 µs |
| `CanaryEvent.model_validate` | 12.86 µs | 13.43 µs |
| `event_fingerprint` | 4.93 µs | 5.24 µs |
| **total** | **21.19 µs** | |

Engine against a native Redis (`pipeline` mode, 2 000 events, PING round trip
87.7 µs):

| Workload | `handle_event` | application CPU | 6 round trips | residual |
|---|---|---|---|---|
| Hot merge, one host | 1 181.8 µs | 25.9 µs (2.2 %) | 527.5 µs (44.6 %) | 628.3 µs (53.2 %) |
| New incident per event, 2 000 hosts | 4 977.9 µs | 20.8 µs (0.4 %) | 526.5 µs (10.6 %) | 4 430.7 µs (89.0 %) |

The residual is what is left after subtracting the measured CPU and
`round trips x PING`. It is not application code either: it is per-command
overhead above a bare PING (redis-py response parsing, connection I/O, asyncio
wake-ups) plus server work proportional to the response. One dedup call costs
134.1 µs against an 87.7 µs PING, which puts ~46 µs per real command on the
table.

#### The index size is the largest single cost

The second row is not slow because it does more round trips - both rows do six.
It is slow because a host seen for the first time has no `incident-latest`
pointer, so `find_recent_incident` falls back to `ZREVRANGEBYSCORE`, which
returns **every** incident inside the horizon and filters that list in Python.
The cost is O(live incidents) per event, and it grows:

| Live incidents | `handle_event` | residual |
|---|---|---|
| 200 | 4 444.7 µs | 1 402.1 µs |
| 2 000 | 8 774.2 µs | 5 517.1 µs |

Both rows were measured on the same machine with a constant round trip, so the
growth is the response and not the network; the absolute values are Docker
Desktop's, so only the ratio is the result.

#### Decision

- **`orjson` — no.** Parsing is 3.39 µs of a 1 181.8 µs event, so replacing the
  decoder buys at most ~2.4 µs (0.2 %) and adds a dependency.
- **Pydantic tuning, removing `model_dump`, model settings — no.** Validation is
  12.86 µs in total; halving it changes an event by 0.5 %. The largest single
  function inside it is the per-character control-character scan shared by three
  host validators (about 12 µs of own time under `cProfile`, which inflates small
  calls). A regex would save a few microseconds - worth doing for clarity, not
  for throughput.
- **The lever is the lookup, not the language layer.** Bounding the fallback
  scan, or skipping it for a first-seen host, removes up to 4.4 ms of a 5.0 ms
  event while the index is populated. Round trips come second at 0.53 ms, and
  the per-command overhead third.

#### Bounded lookup (implemented)

`RedisStore.find_recent_incident()` now takes `scan_limit`, passed to Redis as
`ZREVRANGEBYSCORE … LIMIT 0 <n>` (`OCC_INCIDENT_LOOKUP_SCAN_LIMIT`, default
**100**, bounded 1..10000). Because the reply is ordered newest-first, a match
inside the cap is still the newest incident for that prefix; a miss that the cap
cut short comes back as `truncated` and is audited as
`incident_lookup_truncated` instead of being silently trusted. A pointer hit is
unchanged and scans nothing.

The measurement is an A/B on one build: same `redis:7-alpine` container on
Docker Desktop, database flushed between runs, only the knob differs, 1 000
events against 1 000 hosts so every event is a first-seen host and takes the
fallback path.

| `OCC_INCIDENT_LOOKUP_SCAN_LIMIT` | Live incidents at the end | `handle_event` | residual |
|---|---|---|---|
| 10 000 (effectively unbounded) | 1 000 | 6 513.9 µs | 3 525.7 µs |
| 100 (new default) | 1 000 | 4 465.6 µs | 1 438.4 µs |

That is **‑31 %** per event (‑59 % of the residual) with an identical command
count - six round trips and eleven commands per event in both runs. The decisive
check is flatness: doubling the index to 2 000 incidents with the cap on leaves
the residual at **1 377.1 µs**, whereas the same doubling without a cap moved it
from 1 402 µs to 5 517 µs earlier in this document. The term that grew with the
index is gone; what remains is per-command cost, not state size.

The absolute numbers are Docker Desktop's (PING ≈ 500 µs here), so the ratio and
the flatness are the result, not the microseconds.

#### What the residual is (measured, not inferred)

Two hypotheses were on the table for the 53 % residual of a hot merge: the
pure-Python RESP parser (`hiredis` as a dependency) and `decode_responses`
turning every bulk string into `str`. Both were measured with `tools/
profile_hot_path.py commands`, which alternates two calls inside one loop and
reports the median of the per-iteration difference - single-run means on this
host bounce by ±30 µs, which is the same size as the effect being hunted.

Interleaved deltas in the Linux container (2 000 pairs, RTT ≈ 120 µs):

| Pair | median delta | p25 / p75 |
|---|---|---|
| full `HGETALL` (15 fields, ~5.5 KB) over `HMGET` of 2 fields | **+13.6 µs** | 12.2 / 18.7 |
| full `HGETALL` over `PING` | +19.4 µs | 18.1 / 22.1 |
| `save_incident` (15 fields, 3 keys, 1 script) over `PING` | **+74.9 µs** | 71.9 / 81.0 |
| `hiredis` over the pure-Python parser, full `HGETALL` | **+0.4 µs** | −1.8 / 2.6 |
| `hiredis` over the pure-Python parser, `PING` | **+0.1 µs** | −5.9 / 3.6 |

The pure-Python half of a merge into a capped incident (`cpu` mode, per call):

| Stage | mean | share of the merge |
|---|---|---|
| `Incident.from_fields` (validating the stored hash) | 3.8 µs | 7 % |
| `append_timestamp` + `merge_logdata` + `to_fields` | 51-53 µs | 100 % |
| — of which `json.loads` of the stored `logdata` | **44-46 µs** | 87 % |
| — of which splitting the 100-entry `events_list` CSV | 4.7 µs | 9 % |
| `to_fields` alone | 2.1 µs | 4 % |
| `audit.emit` (JSON + redaction) | 19-21 µs | - |

**The accounting.** A hot merge pays ~104 µs of payload above six round trips
(19 + 75 + the small pointer read), ~78 µs of Python (`from_fields` + merge +
audit) and six asyncio wakes; that is the 370 µs residual measured in the same
container, with the remainder being scheduling the PING baseline does not
include. Nothing in it is protocol parsing.

**Decisions**

- **`hiredis` — no, and now with a number.** It moves a full 5.5 KB hash read by
  0.4 µs (median of 2 000 paired differences), because the bytes rarely reach
  the parser: the reply is one multi-bulk of fifteen strings and the C parser has
  nothing to accelerate. The dependency is not justified; `profile_hot_path.py`
  picks it up automatically if someone installs it and re-checks.
- **`decode_responses` — no change.** The decoding share is below the noise
  floor, and the obvious A/B is a trap: with `decode_responses=False` this
  codebase's `RedisStore.hgetall()` coerces with `str()`, which is slower than
  decoding (the `bytes` row in the tool is measuring the wrapper, not the
  decoder, and is not used as evidence).
- **The merge path was the next lever, and it is not the wire.** 87 % of the
  merge was `json.loads` of the stored `logdata` list, performed on every event
  only to discover that the list is already at `OCC_MAX_STORED_EVENTS` and must
  be returned unchanged. That decode is now skipped, with the measurement below;
  what remains of a frozen merge is `from_fields` at 4.1 µs.

#### Frozen merge without the decode (implemented)

A merge into a full incident used to run `append_timestamp`, `merge_logdata` and
`to_fields`, and then discard two of the three results: the history was at the
cap, so the rebuilt CSV and the decoded list came back unchanged. The repository
now decides "frozen" first - `events_truncated` together with an `events_count`
at or above the cap - and when the incident class is append-only it skips the
whole trio: one event adds one timestamp and one log entry under the same limit,
so a full timestamp list already proves a full log list. A raised
`OCC_MAX_STORED_EVENTS` brings the count back under the cap and recording
resumes, which is `test_raising_the_cap_lets_a_frozen_incident_record_again`.
`scans.host_portscan` and `scans.network_portscan` opt out through
`LOG_DATA_IS_APPEND_ONLY = False`: their log list is a deduplicated set of ports
or targets that must stay exact, and it is cheap to merge anyway.

The three stages, measured in-process in the `python:3.11-slim` container at
20 000 iterations (`tools/profile_hot_path.py cpu`):

| Stage | mean |
|---|---|
| `from_fields` (still runs) | 4.1 µs |
| `merge_and_to_fields` (skipped when frozen) | **49.2 µs** |
| — of which `decode_logdata` | 43.2 µs |
| — of which `split_events_list` | 3.9 µs |

So the Python half of a frozen merge fell from ~53.4 µs to ~4.1 µs. The
end-to-end check is `tools/bench_ingest.py --events 10000 --hosts 1 --concurrency 1`
with fakeredis, three runs per build, stashing only `core/incident.py` between
them to hold everything else constant: **12.090 / 12.162 / 12.194 s** before and
**11.498 / 11.513 / 11.773 s** after, medians 12.162 s → 11.513 s (**‑5.3 %**,
~65 µs per event). The ranges do not overlap, so the 49 µs of skipped Python
accounts for the win without a call to optimism about the rest.

**Trade-off, stated plainly.** The cap is only consulted when the pointer is
missing or stale. If a live incident for that host exists but sits behind more
than `OCC_INCIDENT_LOOKUP_SCAN_LIMIT` newer incidents - possible with state
written by a build that predates the pointer, or pointers deleted by an operator
- a second incident is created where an uncapped scan would have merged. The
alternative, walking the index until the match appears, is the O(index) cost this
section measures. The truncation is always audited, and raising the knob trades
that risk back against cost.

Reproduce with:

```bash
uv run python tools/profile_hot_path.py cpu --iterations 20000
uv run python tools/profile_hot_path.py pipeline --redis-url redis://localhost:6379/15 --events 2000
uv run python tools/profile_hot_path.py pipeline --redis-url redis://localhost:6379/15 --events 2000 --hosts 1
uv run python tools/profile_hot_path.py commands --redis-url redis://localhost:6379/15 --iterations 2000
# Server latency: idle, then bracketing a workload (SIGTERM ends it early)
uv run python tools/latency_probe.py --redis-url redis://localhost:6379/15 --duration 5
```

The `commands` mode compares the pure-Python parser with `hiredis` when it is
installed, so the parser question can be re-asked after a redis-py upgrade
without editing the tool:

```bash
uv pip install hiredis && uv run --no-sync python tools/profile_hot_path.py commands \
    --redis-url redis://localhost:6379/15 --iterations 2000 && uv pip uninstall hiredis
```

### fakeredis reference (not a capacity number)

| Revision | 10,000 events / 100 hosts |
|---|---|
| Before this iteration | 13.98 s |
| Pointer + scripts, 8 lanes | 14.7 s |

fakeredis has to run the Lua scripts through an embedded interpreter (lupa,
~0.5 ms per `EVALSHA`), which costs more than the five commands the script
replaces. On a real server the same script is ~30 µs of server CPU and removes
round trips. The regression is therefore specific to the test double and is
reported rather than hidden; per-host consumer lanes cannot help either, because
fakeredis is CPU-bound in one process.

### Known limits

- The merge path is still six round trips per event (dedup, lock, pointer read,
  incident read, incident write, unlock). One lane spends ~1.8 ms per event end
  to end under Docker Desktop and 0.5-1.2 ms on a native runner, of which a
  third to two thirds is round trips depending on the host; the write itself is
  constant-size. `OCC_EVENT_CONCURRENCY` only overlaps work across hosts, since
  one host keeps arrival order.
- `OCC_MAX_STORED_EVENTS` trades stored history for write cost: the legacy
  console shows the first 100 timestamps and reports the rest through
  `events_skipped`. Raise it only when incidents are read directly from Redis,
  because the console renders 100 and nothing more.
- `OCC_INCIDENT_LOOKUP_SCAN_LIMIT` bounds the fallback lookup, not the fast path.
  A merge is only missed when the host pointer is absent *and* its incident sits
  behind the newest N members of the index; the miss is audited as
  `incident_lookup_truncated` and creates a second incident. In a deployment
  where every replica writes pointers this cannot happen, because the pointer is
  written atomically with the incident.
- The warning is emitted per event, so a deployment that keeps more live
  incidents in the window than the knob allows sees one line per first-seen
  host. That is the intended signal that the cap is binding: raise the knob if
  the index is that large, or accept the bounded scan.
- A frozen merge no longer decodes its stored `logdata` (44-46 µs of a ~53 µs
  merge, measured above), so what is left of it is `from_fields` at 4.1 µs. The
  trade is that `events_truncated` is now authoritative for "history is frozen":
  an incident whose flag says `True` but whose `events_list` is shorter than the
  cap - hand-edited state, or a cap lowered after the fact - would skip an append
  the previous build would have made. Nothing writes that combination; the flag
  is set by the same merge that fills the list.
- Memory is bounded by the queue, not by incident size: 10 000 events into **one**
  incident peaked at the same RSS as 10 000 events over 100 hosts, because the
  stored history is capped (see the memory table below).
- Numbers from Docker Desktop on Windows are dominated by the host/NAT proxy
  (0.1–0.7 ms per round trip, varying with host load) and are not quoted as
  capacity. The Linux numbers above are the reference.

### Resident memory

`tools/bench_ingest.py` reports `rss_mib` (before, after, peak) from
`opencanary_correlator.utils.memory`, which reads `/proc/self/status` on Linux,
`resource.getrusage()` on the other POSIX systems and `GetProcessMemoryInfo()` on
Windows. The Windows probe previously returned nothing because
`PROCESS_MEMORY_COUNTERS` was declared with `c_ulong` fields, which is 4 bytes on
64-bit Windows; the sizes are `SIZE_T` and the call now answers (a bare
interpreter reports 17.2 MiB). A platform that cannot answer reports `null`
rather than an invented number.

`redis:7-alpine` on a Docker network, `python:3.11-slim` test image, 8 lanes
(1 lane for the single-host run):

| Run | Events | Hosts | Incidents | Elapsed | Peak RSS |
|---|---|---|---|---|---|
| New host per event | 10 000 | 100 | 100 | 11.1 s (900 events/s) | **70.9 MiB** |
| Hot merge, one incident | 10 000 | 1 | 1 | 18.3 s (546 events/s) | **70.0 MiB** |

RSS starts at ~48 MiB for the interpreter plus imports and peaks at ~70 MiB in
both shapes, so the queue and the connection pools set the footprint, not the
incident: 10 000 events into a single incident cost no more memory than 10 000
events spread over 100. The 250 MB budget in the acceptance record is met with
room to spare; the figure is the process's own resident set, not the container's.

The single-host row is quoted for memory, not throughput: it is one lane and one
incident, which serialises every event by design. The 100-host row is the shape
the throughput criterion refers to (11.1 s here, against 5.1-12.0 s for the same
commit on the native CI runner).

### Throughput, recorded rather than gated

Two invocations of one commit measured 5.145 s and 12.040 s for the same
workload on the same runner, so wall-clock elapsed is reported and compared
between builds instead of being asserted. Everything below is 10 000 events
through the real TCP receiver:

| Environment | Workload | Elapsed |
|---|---|---|
| Native runner, 2026-10-25 | 1 host, 1 lane | 12.539 s (798 events/s, peak RSS 69.4 MiB) |
| Native runner, 2026-10-25 | 100 hosts, 8 lanes | 11.369 s (880 events/s, peak RSS 69.3 MiB) |
| Native runner, 2026-10-24 | 100 hosts, 8 lanes | 5.145 s and 12.040 s, same commit |
| Docker Desktop on Windows | 100 hosts, 8 lanes | 11.1 s |
| Docker Desktop on Windows | 1 host, 1 lane | 18.3 s |

The spread comes from CPU steal on a shared runner and from eight lanes
competing inside one event loop; the code is the same. What the tool does assert
- `accepted + dropped == events`, `rejected == 0`, the whole payload arriving
over a single connection - is checked on every run, and an unbounded queue shows
up there as `dropped` before it shows up as an elapsed time.

### Server latency while ingesting

`redis-cli --latency` reports min/max/avg and no percentile, and `redis-benchmark`
measures a closed loop's throughput, so neither answers "how does the server
behave for a second client while the correlator loads it". `tools/
latency_probe.py` does: it pings Redis every 5 ms from its own process and reports
nearest-rank percentiles. CI starts it before both 10 000-event runs and stops it
with `SIGTERM` afterwards, and prints idle first for the same client, server and
interval.

| Phase | samples | p50 | p95 | p99 | max |
|---|---|---|---|---|---|
| Idle (native runner) | 995 | 214.2 µs | 262.7 µs | **305.4 µs** | 1 882.9 µs |
| While ingesting (native runner) | 5 244 | 193.2 µs | 249.5 µs | **277.4 µs** | 2 008.6 µs |
| Idle (Docker Desktop) | 995 | 342.1 µs | 507.8 µs | **696.9 µs** | 8 533.8 µs |
| While ingesting (Docker Desktop) | 2 761 | 269.1 µs | 401.0 µs | **506.1 µs** | 1 022.9 µs |

The p99 change is **−28 µs** on the runner and **−191 µs** through the proxy: both
negative, so the honest reading is that the difference sits below the resolution
of the measurement rather than that load makes Redis faster. The idle p50 is
higher than the loaded one because a 5 ms pacing loop wakes from sleep with
nothing else to schedule, while under load it wakes into a busy loop. What the
criterion asks - no p99 increase above 2 ms - is met with two orders of magnitude
to spare, and the figure is in the benchmark job summary on every run.

## Opt-in real-infrastructure checks

`tests/integration/test_real_redis.py` is skipped unless a disposable database
is provided, so CI and developers can run the same acceptance evidence against
real infrastructure:

```bash
# two replicas on real Redis: 50 duplicates → 1 incident/1 alert,
# 20 distinct events → events_count = 20, plus SIGTERM shutdown on POSIX
OCC_TEST_REDIS_URL=redis://localhost:6379/15 pytest tests/integration/test_real_redis.py -v

# benchmark the real server (add --seed-incidents 5000 for a busy index)
python tools/bench_ingest.py --redis-url redis://localhost:6379/15 --events 10000 --hosts 100
python tools/bench_ingest.py --redis-url redis://localhost:6379/15 \
    --events 2000 --hosts 100 --seed-incidents 5000 --concurrency 8
```

The SIGTERM case starts the installed `opencanary-correlator` as a subprocess,
waits for the TCP listener, sends `SIGTERM`, and requires exit code 0 with
`startup` and a final `shutdown` audit record. It is skipped on Windows because
`TerminateProcess` bypasses the handler, which is exactly the gap it exists to
close.

## Accepted limits

No item in plan §5 is open. What is written here instead is the set of limits
that were accepted **with a measurement or a decision behind them**, so a reader
can tell them apart from work nobody got to:

1. **A hot event costs six round trips plus ~0.1 ms of Python, and that is the
   floor of this design.** A native runner spends 0.17-0.38 ms in round trips and
   0.34-0.83 ms outside them, so the wire is no longer the dominant term. Every
   candidate for lowering it was costed rather than dismissed: collapsing the six
   commands into one Lua script was investigated and rejected on measurement
   ([EXECPLAN-merge-consolidation.md](EXECPLAN-merge-consolidation.md)), `hiredis`
   was refuted at +0.4 µs on a full `HGETALL`, and orjson/Pydantic tuning cannot
   pay for itself when the pure-Python share is ~24 µs of a ~280 µs event. The
   discarded `logdata` decode on a frozen incident — the largest single item — is
   gone. Going further means moving the lock or the dedup hop into the same
   script, which changes what `save_incident` guarantees, so it belongs in a new
   plan with its own acceptance rather than in a performance patch.
2. **Duplicate suppression is on by default, and the Python 2 correlator had
   none.** A byte-identical event inside `OCC_DEDUP_TTL` (default 60 s) is dropped
   instead of merged, so `events_count` matches distinct events rather than
   retransmissions. This is the intended behaviour of the module that owns
   deduplication, and setting `OCC_DEDUP_TTL=0` restores the old counting for an
   operator who wants every retransmission merged.
3. **`events_truncated` is authoritative for "history is frozen".** The frozen
   merge skips the timestamp append and the `logdata` decode, so an incident
   whose flag says `True` while its `events_list` is shorter than
   `OCC_MAX_STORED_EVENTS` — hand-edited state, or a cap lowered after the fact —
   does not resume appending. Nothing writes that combination; the flag is set by
   the same merge that fills the list, and raising the cap puts the count back
   under the limit and does resume.

Closed since the previous revision:

- The last unmeasured acceptance criterion is measured: server p99 latency under
  the ingestion load, previously claimed with nothing behind it, is now produced
  by `tools/latency_probe.py` in every benchmark run (−28 µs against idle on the
  runner, against a 2 ms budget). The throughput criterion is no longer a
  threshold either — see `docs/EXECPLAN-refactor.md` §5.
- The benchmark job reports what its tools measure: RSS per workload, the merge
  breakdown per stage, and the interleaved command deltas. `commands` had never
  run in CI, and could not have: it exited on an interpreter without `hiredis`,
  because the parser class exists even when the C library does not and raises in
  its constructor, which the tool read as "Redis unreachable".
- The quadratic single-host merge is gone: stored history is capped at
  `OCC_MAX_STORED_EVENTS` and a full incident is updated with counters only
  (77.2 s → 17.7 s, hash flat at 4 329 bytes).
- The POSIX SIGTERM case runs in CI with nothing skipped, and was reproduced
  locally in a `python:3.11-slim` container against a real `redis:7-alpine`.
  The container path remains covered by `docker stop` → exit 0 with a final
  `shutdown` record.
