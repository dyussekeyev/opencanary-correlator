# ExecPlan: Deep Refactoring of OpenCanary Correlator

Status: **complete 2026-10-24** — Milestones 1–6 done; see `docs/validation.md` for measured results and open items.
Proposed: 2026-10-24. Revised: dispatcher set confirmed (SMTP, generic webhooks, Slack, Telegram, Discord; no SMS in phase 1).

## 1. Goal

Replace the Python 2.7 / Twisted / synchronous-Redis implementation of `opencanary-correlator` with a Python 3.11+ `asyncio` service that **accepts the unmodified wire format of `opencanaryd`** (`SocketJSONHandler`: newline-delimited JSON over TCP, verified in `opencanary/logger.py` → `makePickle() = record.getMessage() + "\n"`), validates every event with Pydantic v2, keeps all correlation state in Redis via `redis.asyncio` so any number of replicas can run behind a load balancer, emits JSON audit logs with `timestamp/component/action/status/details`, and is enforced by `ruff` + strict `mypy` + `pytest`/`pytest-asyncio`.

Alert delivery is plugin-based (`BaseDispatcher`) with these channels in phase 1: **SMTP**, **generic SIEM webhook**, **Slack**, **Telegram**, **Discord**. Legacy Twisted, the deprecated `mandrill` client, `twilio==4.4.0`, `setup.py` and implicit-relative-import modules are removed. SMS is deliberately out of phase-1 scope; it is designed as a later plugin.

The legacy Redis key layout and incident field names are preserved so existing console/dashboards keep reading the same data.

## 2. Progress and Milestones

- [x] Milestone 1: Codebase Audit & Tooling Setup (no behaviour change yet) — 2026-10-24
- [x] Milestone 2: Pydantic Schemas & Constants Registry — 2026-10-24
- [x] Milestone 3: Asyncio TCP Receiver (`SocketJSONHandler`-compatible) + Syslog Receiver — 2026-10-24
- [x] Milestone 4: Stateless Correlation Engine & Async Redis Integration (windows, dedup, incidents) — 2026-10-24
- [x] Milestone 5: Dispatcher Plugins (SMTP / Webhook / Slack / Telegram / Discord) & JSON Audit Trail — 2026-10-24
- [x] Milestone 6: Legacy Removal, Docker, Documentation, Parity Sign-off — 2026-10-24

### Progress log

**2026-10-24 — Milestone 1.** Removed `setup.py`, `requirements.txt`, `bin/opencanary-correlator`. Added `pyproject.toml` (PEP 621, hatchling, console script), `src/opencanary_correlator/` (`__init__`, `py.typed`, `__main__`, `cli.py` stub with `--version` only), `.env.example`, `.gitignore` entries and `tests/conftest.py` + `tests/unit/test_tooling_smoke.py`. Local venv `.venv` on Python 3.14.9 with pydantic 2.14.1, pytest 9.1.1, pytest-asyncio 1.4.0, ruff 0.17.2, mypy 2.4.0. Gates: `ruff check` clean, `ruff format --check` clean, `mypy src` clean, `pytest` 7 passed. Known temporary limitation: `python -m opencanary_correlator` from the repository root resolves to the legacy Python 2 package until Milestone 6 deletes it (the installed console script and pytest's `pythonpath = ["src"]` are unaffected). The coverage gate is configured (`fail_under = 85`) but only becomes meaningful once real modules exist in Milestone 2.

**2026-10-24 — Milestone 2.** Added `constants.py` (complete `LogType` registry incl. post-2016 types, incident prefix map, legacy Redis key names, `DEFAULT_EVENT_FIELDS`), `schemas.py` (`CanaryEvent`, typed `LogDataModel` accessors, `IncidentRecord`), `redaction.py` (shared secret masking and control-character sanitising), `audit.py` (`AuditEvent`/`AuditLogger` JSON lines, bounded async `RedisLogHandler`) and `config.py` (`Settings` on pydantic-settings with `OCC_` env prefix, `SecretStr` credentials, comma-separated lists, legacy `.conf` importer). 77 tests; coverage 95.7 % of `src`; ruff and `mypy --strict` clean. Deviations: `redaction.py` was added as a shared module (not in the original file list) because both audit and schema redaction need it; `pytest` now runs coverage by default and `*/__main__.py` is omitted from measurement (covered instead by a subprocess test). Legacy Tree remains untouched.

**2026-10-24 — Milestone 3.** Added `connectors/base.py` (receiver/dispatcher ABCs, `EventSink`/`RateLimiter` protocols, `ConnectorRegistry`), `connectors/receivers/_pipeline.py` (bounded queue, single consumer, rate limiting, audit, counters), `connectors/receivers/_tcp.py` (shared asyncio protocol: line framing, 64 KiB cap, partial-line-only timeout, connection cap, admission tasks), `tcp_json.py` (`SocketJSONHandler` listener) and `syslog.py` (RFC 3164/5424 parser, RFC 6587 octet-counting + newline framing, UDP receiver, synthetic events for plain text). 115 tests, coverage 90.1 %, ruff/mypy clean. Compatibility findings during testing: Python's `SysLogHandler` terminates TCP messages with NUL rather than a newline, so NUL is now accepted as a frame delimiter; a JSON body that follows an unrecognised syslog header is still recognised as an event. Deviations: two shared receiver modules (`_pipeline.py`, `_tcp.py`) were introduced beyond the original file list to avoid duplicating lifecycle/hardening code between the TCP and syslog receivers. Integration tests import a local `helpers` module because the legacy root package still shadows `opencanary_correlator`; this disappears in Milestone 6.

**2026-10-24 — Milestone 4.** Added `storage/keys.py` (byte-identical legacy key layout), `storage/redis_store.py` (async client, transactional pipelines, dedup, distributed lock, incident persistence), `storage/queries.py` (async read side with the console JSON shape), `core/windows.py` (sliding window, distinct-set window, dedup cache, event fingerprint), `core/incident.py` (16 incident types, legacy report formatters, merge rules, atomic create-or-merge repository), `core/rules/` (login, SMB, host-portscan, network-portscan) and `core/engine.py` (dedup, rule routing, fault-isolated dispatcher fan-out with per-channel timeout). New setting `dispatch_timeout` (default 10 s). 159 tests, coverage 90.3 %, ruff/mypy clean; two-replica tests prove 50 duplicate events yield one incident/one notification and 20 concurrent distinct events merge into a single incident with `events_count = 20`. Deviations: (1) `core/rules/base.py` was added because keeping the `Rule` ABC in the package `__init__` created an import cycle; (2) create-or-merge uses a short-lived `SET NX PX` lock plus transactional `HSET`/`ZADD` instead of Lua scripts, so the same code path is exercisable against fakeredis; (3) the dedup fingerprint also includes `src_port`, so separate connections are never collapsed; (4) port-scan incidents always store the legacy `5002`/`5003` logtype (the Python 2 code only set it when merging); (5) `utils/time.py` was ported now because the query layer needs it.

**2026-10-24 — Milestone 5.** Added `connectors/dispatchers/base.py` (`RetryPolicy`, shared `httpx.AsyncClient` ownership, retries with exponential backoff and jitter, `Retry-After` capped at 60 s, Redis-backed `CircuitBreaker` shared between replicas), the five channels (`webhook.py` for Elastic/Wazuh/Splunk shims, `slack.py`, `telegram.py` with a `SecretStr` token and 4096-char truncation, `discord.py` switching to an embed above 2000 chars, `smtp.py` on `aiosmtplib` with STARTTLS and optional auth), `health.py` (`/healthz` and `/readyz` with a Redis ping, 503 when degraded), `storage/rate_limit.py` (per-IP connection and per-node event limits on Redis) and `cli.py` (`argparse`, legacy `--config` import, `--check-config` with a redacted summary, signal handling, startup/shutdown audit records, receiver + engine + health supervision). 198 tests, coverage 89.8 %, ruff/mypy clean. Deviations: (1) the socket-level dispatcher test is `tests/integration/test_dispatcher_delivery.py` because `tests/unit/test_dispatchers.py` already existed and the two test directories are not packages, so identical basenames collide at collection; (2) `store` and `incident_factory` fixtures moved from `tests/unit/conftest.py` to `tests/conftest.py` so integration tests share them; (3) `TelegramDispatcher` accepts a plain `str` token as well as `SecretStr` and coerces it, because passing a raw string previously raised `AttributeError`; (4) the CLI audit stream starts with `receiver_started` (emitted by the receiver pipeline) rather than `startup`, so the assertions check set membership plus `startup`/`shutdown` presence; (5) `HealthServer` covers readiness only — no `/metrics` endpoint is shipped in this phase; (6) the M1 smoke test that asserted `main([])` printed help was updated: running without `OCC_REDIS_URL` now exits 2 with a configuration error.

**2026-10-24 — Milestone 6.** Deleted the Python 2 tree (`opencanary_correlator/`, 17 files including `opencanary_correlator.conf`); the repository now ships only `src/opencanary_correlator`. Removed the ruff `extend-exclude` and mypy `exclude` entries that had been hiding the new package from those tools — this surfaced 18 real findings (unused imports, `asyncio.TimeoutError` alias, bind-all defaults, an empty ABC hook, two long lines, one unsorted import block), all fixed, so `src` is now formatted by `ruff format` and checked by both gates. Rewrote `README.md` (compatibility contract, OpenCanary logger snippet verified against the upstream docs, legacy `.conf` migration, channel table, scaling, Docker), added `docs/architecture.md`, `docs/audit-events.md` and `docs/validation.md`, plus `Dockerfile` (multi-stage, unprivileged uid 10001, `HEALTHCHECK`), `docker-compose.yml` (Redis + correlator, read-only root, `cap_drop: ALL`) and `.dockerignore`. Tests updated: the module entry point now runs from the repository root (no legacy shadowing) and the legacy-tree smoke test covers the deleted package and `.conf`. Final gates: `ruff check`/`format --check` clean, `mypy` clean, 202 tests, coverage 90.33 %. Packaging proven by building the identical wheel (same sha256) from the exact Docker `COPY` set. Deviations and limitations: the Docker daemon was not running, so `docker build`/`compose up` and the container `HEALTHCHECK` are unverified (compose config validated offline); no live Redis, so all integration numbers are on fakeredis; the 10k-event benchmark took 14.85 s with 100 sources (target < 10 s) and 77.2 s for a single merged incident, because every merge rewrites the growing `events_list` — recorded as an open issue in `docs/validation.md` instead of being reinterpreted as a pass; SIGTERM was not delivered to a live process on Windows.

**2026-10-24 — Acceptance tooling.** Closed the parts of `docs/validation.md` that do not need new infrastructure: added `tests/integration/test_real_redis.py` (opt-in via `OCC_TEST_REDIS_URL`: two replicas on a real server, 50 duplicates → one incident/one alert, 20 distinct events → `events_count = 20`, plus a POSIX SIGTERM test of the installed CLI) and [tools/bench_ingest.py](tools/bench_ingest.py) (`--events`, `--hosts`, `--redis-url`; fakeredis fallback). Verified the exact Dockerfile `HEALTHCHECK` command against a live `/healthz` (exit 0) and after shutdown (exit 1). Re-measured the 10k/100-host workload with the harness: 13.98 s, 716 events/s, 0 dropped, 100 incidents. Still blocked by the machine: no Docker daemon/Docker Desktop, no Redis server, no POSIX host; those runs are listed as open items with copy-paste commands.

**2026-10-24 — Rate limiter window fix.** Closed a P1 defect found during acceptance analysis: `RedisStore.increment_with_expire()` refreshed the TTL on every increment, so a node sending continuously above its budget never left the window and stayed blocked until a full minute of silence. Added `RedisStore.increment_fixed_window()` — `SET NX EX` creates the counter once, `INCR` only counts — and switched `RedisRateLimiter` to it; `increment_with_expire` remains for the circuit breaker, where extending the failure stream is intended. The limiter now accepts `window_seconds` for deterministic tests, and `test_window_resets_even_while_traffic_continues` rejects a request mid-window and accepts it after the window while traffic continues. 203 tests.

**2026-10-24 — Per-incident horizons.** Restored the legacy compatibility regression found during acceptance analysis. Added `Settings.incident_horizons` (JSON `OCC_INCIDENT_HORIZONS`, keys validated against `INCIDENT_KEY_PREFIX`, values bounded to one week and zero allowed), `Settings.horizon_for()`, and switched `IncidentRepository.record()` from the global horizon to the per-type value. `LEGACY_INCIDENT_HORIZON_KEYS` maps all 16 old keys — including the legacy `httproxy.incident_horizon` typo, `smb.file_open_horizon` and both `scans.*_horizon` keys — and `from_legacy_json()` imports them without reporting them as dropped; an explicit `incident_horizons` override wins per key. `.env.example`, the README migration list and `docs/architecture.md` document the behaviour, and `--check-config` prints the effective map. Tests: environment parsing, unknown/negative/infinite/malformed rejection, legacy import (including that the map does not leak into other incident types), and a repository test proving a 120 s override merges at 61 s and starts a new incident after the extended window. 210 tests, coverage 90.40 %, ruff/format/mypy clean.

**2026-10-24 — Discord 204.** `DiscordDispatcher` now defaults to `expected_status=(200, 204)`: Discord answers a successful webhook execution with `204 No Content`, so the inherited 200-only check reported every real delivery as an error. Existing tests had been passing `expected_status` explicitly and a 200 mock, which masked the defect. The override was removed from the tests, the 204 path is now covered through both `httpx.MockTransport` and a real loopback server that sends a body-less 204, and 200 remains covered as a parameter. 212 tests, coverage 90.41 %, ruff/format/mypy clean.
**2026-10-24 — Console log list.** Closed the last P1 from the acceptance analysis: `RedisLogHandler` existed but nothing ever attached it, so the legacy `logs` list stayed empty and the old console showed no journal. Added `RedisStore.push_log()` (`LPUSH` + `LTRIM` in one transaction, newest first, bounded) and wired the handler into `run_correlator`: it is attached to the `opencanary_correlator` package logger, started before the receivers, removed and drained after dispatchers close but **before** an owned Redis pool is closed, so buffered lines are not lost on shutdown. `tests/unit/test_logs.py` covers the trim and the async drain; `test_cli.py` now asserts that a line logged while the service runs lands in `logs` and that no handler is left on the logger afterwards. 214 tests, coverage 90.43 %, ruff/format/mypy clean.

## 3. Plan of Work

### Audit findings (21 files, 1,216 LOC, last commit `294470d`, 2019-03-14)

| Legacy artifact | Problem | Disposition |
|---|---|---|
| `receiver.py` | Twisted `LineReceiver`, `print >>` syntax, port 1514 hardcoded, `pkg_resources` (gone in modern setuptools), `MAX_LENGTH` enforced only by Twisted | Port to `asyncio.Protocol` with explicit limits; delete file |
| `dispatcher.py` | Star imports, `logmap` built at import time, logger side effects at module load | Replace with explicit rule registry in `core/` |
| `handlers.py` | Portscan logic does non-atomic `exists`/`sadd`/`scard` sequences → duplicate alerts across replicas; bare `traceback` inside `except` | Reimplement atomically (Lua/`SET NX`); rules become declarative |
| `common/incidents.py` | 437 LOC god-module, `deferToThread(notify)` (Twisted), Py2 `has_key`, `simplejson`, `src_host`-only incident keys | Split into `Incident` model + `IncidentStore` + rule classes |
| `common/queries.py` | Implicit relative imports, Py2 `has_key`, calls undefined `get_all_devices()`, `datetime.utcnow()` deprecated | Rewrite async; keep JSON field names (`created_printable`, `events_list`, …) for console parity |
| `common/redismanager.py` | Global sync `StrictRedis` on hardcoded `127.0.0.1`, `db='0'` | `redis.asyncio` pool from `REDIS_URL` |
| `common/config.py` | JSON file only, `bool("False") is True` bug, no env/secrets | `pydantic-settings` (`OCC_` prefix + `.env`), optional legacy `.conf` importer |
| `common/logs.py` | `from queries import write_log` (Py2 implicit relative), logger picked by list index | Structured JSON audit logger |
| `common/notifications.py`, `common/emailer.py` | Deprecated `mandrill` client (PyPI: "Deprecated. Replaced by mailchimp-transactional"), `twilio==4.4.0` (2015, sync), blocking `requests`/`smtplib` | `httpx` + `aiosmtplib` dispatchers behind ABCs |
| `common/utils.py` | Naive `utcnow()`, `string.lstrip` misuse | `utils/time.py`, timezone-aware |
| `setup.py`, `requirements.txt`, `bin/opencanary-correlator` | Py2-era packaging, `setuptools_git`, unpinned drift | `pyproject.toml` (PEP 621) + console script; delete all three |
| `common/constants.py` | Missing post-2016 logtypes (`16001 GIT_CLONE`, `17001 REDIS`, `18001-18005 TCP_BANNER`, `19001 LLMNR`, `20001 MONGODB`, `99000-99009 USER_*`) | Extended registry, unknown types tolerated + audited |

### Strategy

The codebase is small enough for a strangler-fig rewrite rather than a line-by-line Py3 port: build the new `src/` package alongside the legacy tree, keep the legacy code untouched (so nothing is silently lost), port module-by-module with parity tests, then delete the legacy tree in one dedicated commit (Milestone 6). Each milestone is a separate commit/PR and follows TDD — tests are written first or in parallel, per AGENTS.md.

### Compatibility contract (must not change)

- **Transport**: TCP, newline-delimited UTF-8 JSON, default port `1514`; payload is exactly what `SocketJSONHandler.send()` writes. Lines with the `[ERR] '{"…"}'` prefix produced by `PyLogger.error()` are rejected with an audit record, never crash the server.
- **Event schema**: `src_host`, `src_port`, `dst_host`, `dst_port`, `logtype`, `node_id`, `local_time`, `utc_time`, `local_time_adjusted`, `logdata` (object, nested values allowed), plus optional `reported_dst_host`. Missing fields are filled with the same defaults `sanitizeLog()` uses (`""`, `-1`, `1001`, `{}`).
- **Connection lifecycle**: `SocketJSONHandler` keeps its socket open and may stay silent for hours (`retryStart = 0`, keep-alive enabled). Idle timeouts therefore apply only to a **stalled partial line**, never to a quiet but healthy connection.
- **Redis layout preserved**: `incident:<kind>:<src_host>:<ts>`, `incidents` (ZSET, score = created), `device:<sha256[:12]>`, `scan:host:…`, `scan:network:…:targets`, `logs`, `whitelist-ips:*`, `console-setting:*`. Incident hash fields preserved (`events_list` CSV of epochs, `events_count`, `acknowledged`, `notified`, `updated`, `description`, `created`, `logdata` JSON string).
- **Behavioural defaults preserved**: 60 s global incident horizon, host-portscan 5 packets / 50 s, network-portscan 2 targets / 3600 s, per-logtype `*.incident_horizon` overrides.

Note: the Redis layout is internal to the correlator; `opencanaryd` never talks to Redis. Keeping the keys protects legacy dashboards and upgrade continuity, not the honeypot protocol.

### Deliberate removals

Twisted, `zope.interface`, `simplejson`, `PyNaCl` (replaced by `hashlib.sha256`), `pkg_resources`, `mandrill` (deprecated client), `twilio==4.4.0`, `bin/` shell script, `setup.py`, `requirements.txt`.

### Dependencies

Runtime: `pydantic`, `pydantic-settings`, `redis`, `httpx`, `aiosmtplib`.
Dev: `pytest`, `pytest-asyncio`, `pytest-cov`, `fakeredis`, `mypy`, `ruff`.
No ORM/SQLAlchemy in this phase — no relational data is in scope; noted as a future optional plugin.

### Validation policy (why compatibility does not regress)

| Risk | Mitigation |
|---|---|
| `src_host` empty string or hostname | accept bounded `str`, not `IPvAnyAddress` |
| `src_port` / `dst_port` = `-1` | allow `-1…65535` |
| Unknown/new `logtype` | accept any int, audit `event_unrouted`, no incident |
| Nested/heterogeneous `logdata` | `dict[str, Any]` + depth/size limits, `extra="allow"` |
| `[ERR] '…'` non-JSON lines | detect, audit, keep connection |
| Silent long-lived connections | idle timeout only on partial-line stalls |
| Unparsable `local_time` | fall back to receipt time + audit |
| Oversized lines | configurable cap, default 64 KiB (legacy was 16 KiB) |

## 4. Concrete Steps

### Milestone 1 — Audit & tooling (no runtime code touched)

1. Delete `setup.py`, `requirements.txt`, `bin/opencanary-correlator`.
2. Create `pyproject.toml`: PEP 621 metadata (`requires-python = ">=3.11"`), `[project.scripts] opencanary-correlator = "opencanary_correlator.cli:main"`, `[tool.ruff]` (line-length 100, `select = ["E","F","W","I","N","UP","S","B","ASYNC","RUF","ANN"]`), `[tool.mypy]` (`strict = true`, `plugins = ["pydantic.mypy"]`), `[tool.pytest.ini_options]` (`asyncio_mode = "auto"`, coverage gate 85 % on `core`/`schemas`/`connectors`), `[build-system] hatchling`.
3. Create `src/opencanary_correlator/__init__.py`, `py.typed`, `__main__.py`.
4. Create `.env.example` documenting every setting with placeholders only: `OCC_TCP_HOST`, `OCC_TCP_PORT=1514`, `OCC_SYSLOG_ENABLED`, `OCC_SYSLOG_PORT=5514`, `OCC_MAX_LINE_BYTES=65536`, `OCC_PARTIAL_LINE_TIMEOUT=30`, `OCC_MAX_CONNECTIONS=1000`, `OCC_REDIS_URL`, `OCC_INCIDENT_HORIZON=60`, `OCC_SCAN_*`, `OCC_DEDUP_TTL`, `OCC_WEBHOOK_URLS`, `OCC_SLACK_WEBHOOKS`, `OCC_TELEGRAM_TOKEN`/`OCC_TELEGRAM_CHAT_IDS`, `OCC_DISCORD_WEBHOOKS`, `OCC_SMTP_*`, `OCC_LOG_LEVEL`. Add `.env` to `.gitignore`.
5. Create `tests/conftest.py`: `fake_redis` (fakeredis.aioredis), `settings_factory`, `free_tcp_port`, `event_factory`.
6. Create `tests/unit/test_tooling_smoke.py`.

### Milestone 2 — Schemas & constants

7. Create `src/opencanary_correlator/constants.py`: `LogType(IntEnum)` with every legacy value plus `16001/17001/18001-18005/19001/20001/99000-99009`; incident key prefix map; `DEFAULT_EVENT_FIELDS` mirroring `sanitizeLog()`.
8. Create `src/opencanary_correlator/schemas.py`:
   - `CanaryEvent`: bounded `str` hosts, `-1…65535` ports, `LogType | int`, `datetime` with fallback, `logdata: dict[str, Any]` with depth/size limits, `extra="allow"`, control-character rejection, blank `node_id` rejection.
   - Typed `logdata` accessors: `FtpLoginData`, `HttpLoginData`, `SshLoginData`, `SmbFileOpenData`, `UserData`.
   - `IncidentRecord` matching the preserved Redis hash fields.
9. Create `tests/unit/test_schemas.py`: table-driven valid payloads (empty `src_host`, `-1` ports, unknown logtype, hostname `src_host`) and hostile payloads (oversized `node_id`, `logtype: "abc"`, deep nesting, CRLF injection, NaN ports, `[ERR]` line).
10. Create `src/opencanary_correlator/audit.py`: JSON-lines `AuditLogger` with mandatory `timestamp/component/action/status/details`, `AuditEvent` model, async-safe `RedisLogHandler` (bounded list of 1000 preserving `KEY_LOGS`), secret redaction for `PASSWORD`/`TOKEN`-like keys.
11. Create `tests/unit/test_audit.py`.
12. Create `src/opencanary_correlator/config.py`: `Settings(BaseSettings)` with `env_prefix="OCC_"`, `env_file=".env"`, `SecretStr` for tokens, URL/port validators, `from_legacy_json()` mapping `console.*`, `portscan.*`, `networkscan.*` keys; `twilio.*`/`console.mandrill_key` ignored with a warning.
13. Create `tests/unit/test_config.py` (env parsing, legacy import parity, no secret leakage in `repr`).

### Milestone 3 — Receivers

14. Create `src/opencanary_correlator/connectors/base.py`: `BaseReceiver`, `BaseDispatcher`, `DispatchResult`, `ConnectorRegistry` — the only types `core` may import.
15. Create `connectors/receivers/tcp_json.py` (`asyncio.Protocol`):
    - incremental line splitting, `OCC_MAX_LINE_BYTES` (default 64 KiB) → oversized closes connection + `audit(action="event_rejected", reason="line_too_large")`;
    - `OCC_PARTIAL_LINE_TIMEOUT` (default 30 s) armed **only when a partial line is buffered** and disarmed once a full line is delivered — silent keep-alive sockets are never reaped; `OCC_MAX_CONNECTIONS` semaphore; `TCP_NODELAY`/`SO_KEEPALIVE`;
    - guarded `json.loads` → `CanaryEvent.model_validate` → bounded `asyncio.Queue` with drop + audit + metric on overflow;
    - per-IP connection rate limit and per-`node_id` event rate limit via Redis sliding window.
16. Create `connectors/receivers/syslog.py`: TCP RFC 6587 octet-counting and non-transparent framing, plus UDP; parse PRI/version/timestamp/host/app-name; JSON body → `CanaryEvent`; non-JSON body → synthetic `LOG_BASE_MSG` event so `SyslogHandler` nodes still produce data; same guards.
17. Create `tests/integration/test_tcp_json_receiver.py`:
    - compatibility proof: subclass using the exact `SocketJSONHandler.makePickle()` implementation over `logging.handlers.SocketHandler`, payload shaped by `sanitizeLog()` → engine receives an equal `CanaryEvent`, Redis hash has expected key/fields;
    - oversized line, line split across packets, `[ERR] '…'` line, malformed JSON, 200 slowloris connections, and a connection idle for longer than the timeout that must **not** be closed.
18. Create `tests/integration/test_syslog_receiver.py`.

### Milestone 4 — Engine & state

19. Create `storage/keys.py`: byte-identical legacy key builders; `device_hash(node_id) = sha256(...).hexdigest()[:12]`.
20. Create `storage/redis_store.py`: `redis.asyncio` factory (`decode_responses=True`, optional TLS/Sentinel), typed `RedisStore`, Lua scripts `sadd_with_expire`, `zadd_window_and_trim`, `try_create_incident`, `update_incident_event`, `acquire_dedup` (`SET NX EX`); no `KEYS`/`FLUSHDB`.
21. Create `core/windows.py`: `SlidingWindow` (ZSET), `DistinctTargetWindow` (SET + TTL, atomic), `DedupCache` (fingerprint `sha256(node_id|src_host|dst_port|logtype|logdata)`).
22. Create `core/incident.py`: `Incident` model, `IncidentFactory` registry, horizon resolution (rule → `console.incident_horizon` → 60 s), atomic create-or-merge so replicas cannot double-notify, report formatters ported string-for-string (`format_title`, `format_report`, `format_report_short`, SMB and network-portscan bodies).
23. Create `core/rules/{__init__,login,portscan,smb}.py`: `Rule` ABC (`handles`, `evaluate`), 14 login rules, `HostPortScanRule`, `NetworkPortScanRule` (`reported_dst_host` fallback), unknown logtype → `audit(event_unrouted)`.
24. Create `core/engine.py`: `ingest()` → dedup → rate limit → rule dispatch → incidents → dispatcher fan-out with `asyncio.gather(return_exceptions=True)`, per-dispatcher timeout, graceful start/stop with queue drain.
25. Create `storage/queries.py`: async `get_all_incidents`, `get_incident`, acknowledged variants, `clear_incidents`, `write_log`, `get_logs`, console settings, `should_notify`, `get_device` (fixing the undefined `get_all_devices`); same JSON shape including `created_printable`, `created_age`, `events_list` (ms ints), decoded `logdata`, `MAX_EVENT_COUNT = 100`.
26. Create `tests/unit/test_windows.py`, `test_dedup.py`, `test_incident_merge.py`, `test_portscan_rules.py`, `test_engine.py`.
27. Create `tests/integration/test_redis_atomicity.py`: two engines share fakeredis, 50 duplicate events → exactly 1 incident and 1 notification.

### Milestone 5 — Dispatchers & audit wiring

28. Create `connectors/dispatchers/base.py`: `DispatcherConfig`, shared `httpx.AsyncClient` lifecycle, 3-attempt exponential backoff with jitter honouring `Retry-After`, Redis-backed circuit breaker shared between replicas.
29. Create dispatchers:
    - `webhook.py` — generic SIEM POST (Elastic/Wazuh/Splunk HEC), configurable headers, JSON template, strict timeout;
    - `slack.py` — incoming webhook, attachment/blocks payload;
    - `telegram.py` — Bot API `sendMessage`, `SecretStr` token, chat-id list, markdown-safe truncation;
    - `discord.py` — webhook URL, `content` ≤ 2000 chars or `embeds` for the long report, 204/200 handling;
    - `smtp.py` — `aiosmtplib`, STARTTLS/TLS, `EmailMessage`, optional auth.
    All implement `BaseDispatcher`, emit `action="alert_dispatch"` with `status="success|error"`, and never raise into the engine.
30. Create `tests/integration/test_dispatchers.py`: per-channel payload assertions against a local mock server, 500 → retry, timeout, 429 + `Retry-After`, one failing dispatcher not affecting others, Discord 2000-char truncation.
31. Create `cli.py`: `argparse` (`--config`, `--redis-url`, `--log-level`, `--check-config`, `--health-port`), startup/shutdown audit records, signal handling, receiver + engine supervision.
32. Create `tests/integration/test_cli.py`: `--check-config` exit codes, SIGTERM leaves no pending tasks, `/healthz` 200 vs 503.
33. Create `tests/integration/test_end_to_end.py`: full stack with fakeredis and mock endpoints; three `SocketJSONHandler`-format lines → 1 incident hash, 1 delivery to each configured channel, audit lines with the five mandatory fields.

### Milestone 6 — Legacy removal, packaging, docs

34. Delete `receiver.py`, `dispatcher.py`, `handlers.py`, `common/` (all 10 modules), `opencanary_correlator.conf`; verify with `git grep` that nothing references `twisted|mandrill|twilio|simplejson|nacl|pkg_resources`.
35. Rewrite `README.md` (compatibility contract, architecture, install, config table, Docker, scaling, migration from `.conf`).
36. Create `docs/architecture.md`, `docs/audit-events.md`, `docs/validation.md`.
37. Create `Dockerfile` (multi-stage, `python:3.12-slim`, non-root, `HEALTHCHECK`) and `docker-compose.yml` (redis + correlator, ports 1514/5514).
38. Final gate: `ruff check .`, `ruff format --check .`, `mypy`, `pytest`, `docker compose build` green; tick milestones with dates.

## 5. Validation and Acceptance

**Static quality gates**
- `ruff check .` → exit 0; `ruff format --check .` → no reformatting.
- `mypy` (strict) → `Success: no issues found`.
- `git grep -nE "twisted|mandrill|twilio|simplejson|pkg_resources|nacl\.|iteritems|has_key|print >>"` → no matches in shipped code.
- No secret patterns in tracked files; `.env` untracked.

**Test gates**
- `pytest` green with coverage ≥ 85 % on `core`/`schemas`/`connectors`.
- Compatibility test passes: payload produced by the exact `opencanary` `makePickle()` implementation is accepted and yields a legacy-shaped incident hash.
- Duplicate-concurrency test: 50 parallel identical events → exactly 1 incident, 1 notification per channel.
- Receiver hardening: 64 KiB+ line rejected without memory growth; slowloris clients disconnected; **silent keep-alive connection survives past the timeout**.
- Dispatcher tests green for success, retry, timeout, one channel failing without affecting others.

**Functional acceptance (`docs/validation.md`)**
- `docker compose up` → JSON `startup` audit record; Redis reachable.
- Sending `{"logtype": 2000, "src_host": "10.0.0.5", "src_port": 4444, "dst_host": "10.0.0.2", "dst_port": 21, "node_id": "canary-1", "local_time": "2026-10-24 10:00:00.000000", "logdata": {"USERNAME": "admin", "PASSWORD": "x"}}` + `\n` on TCP 1514 creates exactly one `incident:ftplogin:10.0.0.5:<ts>`, one `incidents` member, and one delivery per configured channel in the legacy report format.
- Second identical event within 60 s → `events_count = 2`, no second notification.
- Five SYN events to five ports within 50 s → `scans.host_portscan`; two nodes scanning the same `src_host:dst_port` within 1 h → `scans.network_portscan`.
- Container restart loses no acknowledged state; a second replica produces no duplicate alerts.
- Audit JSON parses line-by-line, every record has the five mandatory fields, no plaintext passwords from `logdata`.

**Performance sanity (measured, reported as numbers)**
- 10,000 events over one connection < 10 s on the dev machine, RSS < 250 MB, no unbounded queue growth; numbers recorded in `docs/validation.md`.
- `redis-cli --latency` p99 increase < 2 ms during the run.

**Rollback**: the legacy tree stays intact until Milestone 6, so any milestone reverts by reverting its commit; tag `legacy-py2` marks the last pre-refactor commit.
