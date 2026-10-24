# Validation and acceptance record

Measured on 2026-10-24.

**Environment:** Windows 11, Python 3.14.9 in `.venv` (project requires 3.11+),
ruff 0.17.2, mypy 2.4.0, pytest 9.1.1, pytest-asyncio 1.4.0, fakeredis
(no live Redis server), Docker CLI 29 with Compose v5.6.1 **but no running
Docker daemon**.

## Static gates

| Command | Result |
|---|---|
| `ruff check .` | All checks passed (legacy root tree removed, so `src/` and `tests/` are now linted too) |
| `ruff format --check .` | 72 files already formatted |
| `mypy src` (`strict = true`, pydantic plugin) | Success: no issues found in 40 source files |
| `pytest` | **214 passed, 3 skipped**, coverage **90.43 %** (gate: 85 %); the skips are the opt-in real-infrastructure checks below |

`grep -rnE "twisted|mandrill|twilio|simplejson|pkg_resources|nacl\.|iteritems|has_key|print >>" src tests`
finds no imports or runtime usage. The only textual mentions are deliberate:
the legacy config keys skipped during migration (`twilio.*`,
`console.mandrill_key` in `config.py`) and a docstring in `storage/keys.py`
noting that PyNaCl was replaced by `hashlib`. `setup.py`, `requirements.txt`,
`bin/opencanary-correlator` and the Python 2 `opencanary_correlator/` package are
deleted; a smoke test asserts they stay gone.

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

Per-incident horizons are covered by configuration tests (environment JSON,
unknown/negative/non-finite rejection, all 16 legacy keys including the
`httproxy` spelling) and by a repository test showing a 120 s override merging
at 61 s and creating a new incident once the extended window closes.

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
mechanism used when replicas run behind a load balancer.

## Dispatcher delivery

`tests/integration/test_dispatcher_delivery.py` runs real loopback servers:

| Scenario | Result |
|---|---|
| Webhook POST over a real socket | success, `Content-Type: application/json`, incident payload |
| 503 → 500 → 200 | three attempts, backoff `[0.1, 0.2]`, success |
| 429 with `Retry-After: 2` | sleeps exactly 2 s, then succeeds |
| 400 | one attempt, `detail = http_400`, no retry |
| Breaker after repeated failures | second delivery `skipped / circuit_open`, no extra request |
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

## Packaging and Docker

| Check | Result |
|---|---|
| `pip wheel .` | `opencanary_correlator-0.2.0-py3-none-any.whl` (64,738 bytes, sha256 `a763ce9d…f638bbae80`) containing sources and `py.typed` only |
| Build context sufficiency | a staging directory with exactly the Dockerfile `COPY` set (`pyproject.toml`, `README.md`, `LICENSE`, `src/`) builds the **identical** wheel hash |
| Fresh install | the wheel installs with its dependencies into an empty venv; `opencanary-correlator --version` → `0.2.0`, `--check-config` → exit 0 |
| Startup failure | `OCC_REDIS_URL=redis://127.0.0.1:6390/0` → one `startup_failed / redis_unavailable` JSON line on stdout, `cannot start: Redis is not reachable` on stderr, exit 1 |
| `docker compose config` | valid; Redis URL forced to `redis://redis:6379/0`, port 1514 published, 5514/8080 exposed, read-only root with `/tmp` tmpfs, `cap_drop: ALL` |
| Container `HEALTHCHECK` | the exact `CMD` extracted from the Dockerfile returns **0** against a healthy `/healthz` and **1** once the listener is stopped, verified from a separate process |
| `docker build` / `docker compose up` | **not run** — no Docker daemon or Docker Desktop binary is installed in this environment |

Consequence: the Dockerfile parses, the wheel it installs is proven, and its
health probe behaves correctly outside a container, but the container smoke test
(`docker compose up`, `startup` audit line, incident creation, image-level
`HEALTHCHECK` status, non-root/read-only runtime) remains **unverified** until it
is run on a host with Docker.

## Performance

Method: `TCPJSONReceiver` + `CorrelationEngine` + `IncidentRepository` on one
loopback connection, 10,000 newline-delimited events in a single write
(2.5 MiB), dedup and merge enabled, **fakeredis** instead of a network Redis,
`OCC_RATE_LIMIT_EVENTS_PER_MINUTE=0`, no dispatchers.

| Workload | Events | Time | Throughput | Dropped | Incidents |
|---|---|---|---|---|---|
| 100 source hosts (100 incidents) | 10,000 | **13.98 s** | 716 events/s | 0 | 100 |
| 1 source host (one merged incident) | 10,000 | **77.2 s** | 130 events/s | 0 | 1 |

Framing/validation alone (no correlation) handles ~28,000 events/s, and the
engine alone (200 distinct events) ~830 events/s.

The repeatable harness is [tools/bench_ingest.py](tools/bench_ingest.py); the
number above comes from
`python tools/bench_ingest.py --events 10000 --hosts 100` (fakeredis). A real
Redis run is one flag away: `--redis-url redis://localhost:6379/15`.

**Acceptance target "10,000 events < 10 s" was not met**: ~14 s with 100
incidents. The single-source case is ~5× slower because every merge rewrites
the growing `events_list` field (and `logdata` merge) — a quadratic cost that
the legacy format inherits. Recorded as an open issue rather than quietly
relabelled as a pass. Profiling attributes most of the remaining time to the
roughly ten Redis round trips per event (dedup, lock, lookup, merge, unlock);
fakeredis implements RESP in Python, so a real Redis server may be faster, but
the command count itself is the structural limit.

RSS was not recorded: the Windows `GetProcessMemoryInfo` probe used by the
benchmark returned no data, so no memory figure is claimed.

Caveats: fakeredis and a Windows loopback are not a Redis/Linux benchmark; the
numbers are indicative and should be re-measured against a real Redis instance
before sizing production capacity.

## Opt-in real-infrastructure checks

`tests/integration/test_real_redis.py` is skipped unless a disposable database
is provided, so CI and developers can run the same acceptance evidence against
real infrastructure:

```bash
# two replicas on real Redis: 50 duplicates → 1 incident/1 alert,
# 20 distinct events → events_count = 20, plus SIGTERM shutdown on POSIX
OCC_TEST_REDIS_URL=redis://localhost:6379/15 pytest tests/integration/test_real_redis.py -v

# benchmark the real server
python tools/bench_ingest.py --redis-url redis://localhost:6379/15 --events 10000 --hosts 100
```

The SIGTERM case starts the installed `opencanary-correlator` as a subprocess,
waits for the TCP listener, sends `SIGTERM`, and requires exit code 0 with
`startup` and a final `shutdown` audit record. It is skipped on Windows because
`TerminateProcess` bypasses the handler, which is exactly the gap it exists to
close.

## Open items

1. Run `docker compose up -d --build` on a Docker host, verify the image builds,
   the container is healthy, an `opencanaryd`-format line creates an incident,
   and the process runs as uid 10001 with a read-only filesystem. No Docker
   daemon or Docker Desktop installation exists on this machine.
2. Set `OCC_TEST_REDIS_URL` and run the opt-in file plus the benchmark's
   `--redis-url` mode against a real Redis server (ideally on Linux). Neither a
   Redis server nor a POSIX host is available here.
3. Decide whether to cap the stored `events_list` (or index incidents per
   `src_host`) to remove the quadratic merge cost; this changes legacy hash
   contents, so it needs an explicit decision.
4. Run the POSIX SIGTERM check from `test_real_redis.py` on Linux; on Windows
   only `stop_event` and handler registration are covered.
