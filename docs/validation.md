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

- **One source host is still quadratic.** 10,000 events from a single host took
  77.2 s before this change, because every merge rewrites the growing
  `events_list`/`logdata` fields (the legacy console reads them as CSV/JSON
  strings). The pointer and lanes do not change that, and fixing it would mean
  changing the incident schema, which is out of scope.
- Six Redis round trips per event remain (dedup, lock, pointer read, incident
  read, incident write, unlock). `OCC_EVENT_CONCURRENCY` overlaps them; it does
  not remove them.
- Numbers from Docker Desktop on Windows are dominated by the host/NAT proxy
  (0.1–0.7 ms per round trip, varying with host load) and are not quoted as
  capacity. The Linux numbers above are the reference.

RSS was not recorded: the Windows `GetProcessMemoryInfo` probe used by the
benchmark returned no data, so no memory figure is claimed.

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

## Open items

1. Decide whether to cap the stored `events_list` (or index incidents per
   `src_host`) to remove the quadratic merge cost; this changes legacy hash
   contents, so it needs an explicit decision.

Closed since the previous revision: the POSIX SIGTERM case now runs in CI
(`294 passed, 0 skipped` in the `test` jobs) and was reproduced locally in a
`python:3.11-slim` container against a real `redis:7-alpine` (`3 passed`); the
container path remains covered by `docker stop` → exit 0 with a final
`shutdown` record.
