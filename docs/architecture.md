# Architecture

The correlator turns a stream of independent honeypot events into a small number
of incidents and delivered alerts. It is a single asyncio process with no
in-process correlation state, so any number of replicas can run behind a load
balancer.

## Runtime topology

```
 canary nodes                    correlator replica                 external
┌────────────┐   TCP 1514   ┌──────────────────────────┐          ┌──────────┐
│opencanaryd │─────────────▶│ TCPJSONReceiver          │          │  Redis   │
│ SocketJSON │              │  line framer → Pydantic  │─────────▶│ windows  │
│  Handler   │              │  → bounded queue         │          │ incidents│
└────────────┘              │  → rate limiter          │          │ locks    │
                            │        │                 │          │ dedup    │
┌────────────┐  TCP/UDP     │        ▼                 │          │ breaker  │
│ SysLog     │ 5514         │ CorrelationEngine        │          └──────────┘
│ Handler    │─────────────▶│  dedup → rules → merge   │
└────────────┘              │        │                 │
                            │        ▼                 │          ┌──────────┐
                            │ Dispatchers              │─────────▶│ SMTP     │
                            │  webhook/slack/telegram/ │          │ HTTP(S)  │
                            │  discord/smtp            │          │ Telegram │
                            └──────────┬───────────────┘          │ Discord  │
                                       │ stdout JSON              └──────────┘
                                       ▼
                              Elastic / Wazuh / Loki
```

`--health-port` adds a tiny HTTP listener (`/healthz`, `/readyz`) for probes.
Configuration is read once at startup; every credential comes from the
environment or `.env`.

## Package map

| Path | Responsibility |
|---|---|
| `config.py` | `Settings` (pydantic-settings, `OCC_` prefix), legacy `.conf` importer, URL/port validation |
| `schemas.py` | `CanaryEvent` (lenient, bounded), typed `logdata` accessors, `IncidentRecord` |
| `constants.py` | `LogType` registry, incident key prefixes, legacy Redis key names, defaults |
| `redaction.py` | secret masking and control-character stripping for audit output |
| `audit.py` | `AuditEvent`/`AuditLogger` JSON lines, `RedisLogHandler` for the bounded console log |
| `connectors/base.py` | `EventSink`, `RateLimiter`, `BaseReceiver`, `BaseDispatcher`, `DispatchResult` — the only types `core` may import |
| `connectors/receivers/_tcp.py` | asyncio stream lifecycle: framing, 64 KiB cap, partial-line timeout, connection cap, TCP keep-alive |
| `connectors/receivers/_pipeline.py` | bounded queue, single consumer, rate limiting, audit, counters |
| `connectors/receivers/tcp_json.py` | `SocketJSONHandler` compatibility: newline-delimited JSON, `[ERR]` tolerance |
| `connectors/receivers/syslog.py` | RFC 3164/5424 envelope parser, RFC 6587 TCP framing, UDP receiver |
| `connectors/dispatchers/base.py` | HTTP client ownership, retry policy, `Retry-After`, Redis circuit breaker |
| `connectors/dispatchers/*.py` | webhook, Slack, Telegram, Discord, SMTP channels |
| `core/windows.py` | sliding window (ZSET), distinct-set window, dedup cache, event fingerprint |
| `core/rules/` | `LoginRule` (14 log types), `SmbFileOpenRule`, host/network port-scan rules |
| `core/incident.py` | 16 incident types, legacy report formatting, merge rules, atomic create-or-merge |
| `core/engine.py` | dedup → rule routing → dispatcher fan-out with per-channel timeout |
| `storage/keys.py` | byte-compatible legacy Redis key builders |
| `storage/redis_store.py` | typed `redis.asyncio` wrapper, transactional pipelines, lock, incident persistence |
| `storage/queries.py` | async read side with the console JSON shape (`created_printable`, `events_list`, …) |
| `storage/rate_limit.py` | per-IP connection and per-node event budgets |
| `health.py` | `/healthz` and `/readyz` with a Redis ping |
| `cli.py` | argument parsing, wiring, supervision, signal handling, audit records |

Dependency direction is enforced by convention: `core` imports only
`connectors/base.py`, never a concrete receiver or dispatcher. Adding a channel
therefore never touches correlation logic.

## Event lifecycle

1. **Frame** — the TCP protocol splits bytes on `\n`, strips a trailing `\r`,
   and rejects any frame above `OCC_MAX_LINE_BYTES` (default 64 KiB) by closing
   the connection with an audit record. A timer is armed only while a partial
   line is buffered, so a silent keep-alive socket from `SocketJSONHandler` is
   never disconnected.
2. **Parse and validate** — JSON is decoded with NaN/Infinity rejected, then
   validated by `CanaryEvent`: ports `-1…65535`, `src_host` up to 255 chars,
   `node_id` 1–128 chars without control characters, `logdata` depth ≤ 5 and
   ≤ 2000 nodes. Every failure produces `event_rejected` with a reason
   (`invalid_utf8`, `line_too_large`, `canary_error_line`, `malformed_json`,
   `non_object_payload`, `schema_validation`, `malformed_syslog`,
   `datagram_too_large`) and the connection keeps working.
3. **Queue** — the event enters a bounded queue (`OCC_EVENT_QUEUE_SIZE`). On
   overflow it is dropped and audited as `event_dropped`; the receiver never
   blocks the event loop.
4. **Rate limit** — the single consumer asks `RedisRateLimiter` for an event
   budget per `node_id` (`OCC_RATE_LIMIT_EVENTS_PER_MINUTE`, `0` disables).
   Budgets use a fixed window whose expiry is written when the counter is
   created and never refreshed, so sustained traffic cannot extend it.
   Over-budget events are audited as `event_rate_limited`.
5. **Dedup** — `event_fingerprint` hashes
   `node_id|src_host|src_port|dst_host|dst_port|logtype|logdata` with SHA-256;
   `SET NX PX` on `dedup:<fingerprint>` (`OCC_DEDUP_TTL`) rejects retransmits,
   audited as `event_deduplicated`.
6. **Route** — every rule is asked `matches(event)`, then `apply(event, now)`.
   A rule raising is audited as `rule_failed` and does not stop the others. If
   no rule matched, the event is audited as `event_unrouted` (this is how new
   `logtype` values stay harmless).
7. **Create or merge** — `IncidentRepository.record()` takes
   `incident-lock:<incident>:<src_host>` (5 s TTL), looks for a live incident
   with the same key prefix inside the horizon, and either merges
   (`events_count += 1`, append timestamp, merge `logdata`) or writes a new
   hash plus its `incidents` ZSET entry in one transaction. Only creation
   returns an incident for delivery; a merge deliberately produces no alert.
8. **Deliver** — incidents fan out to every dispatcher concurrently, each
   bounded by `OCC_DISPATCH_TIMEOUT`. A timeout, exception or non-success
   result is audited as `alert_dispatch` with status `error`; other channels
   are unaffected and ingestion continues immediately.

## Correlation rules

| Rule | Trigger | Horizon |
|---|---|---|
| `login` | `LOG_FTP_*`, `LOG_HTTP_POST_LOGIN_ATTEMPT`, `LOG_SSH_LOGIN_ATTEMPT`, `LOG_TELNET_LOGIN_ATTEMPT`, `LOG_HTTPPROXY_LOGIN_ATTEMPT`, `LOG_MYSQL_LOGIN_ATTEMPT`, `LOG_MSSQL_LOGIN_SQLAUTH`, `LOG_MSSQL_LOGIN_WINAUTH`, `LOG_TFTP`, `LOG_NTP_MONLIST`, `LOG_VNC`, `LOG_SNMP_CMD`, `LOG_RDP`, `LOG_SIP_REQUEST`, `LOG_MONGODB_LOGIN_ATTEMPT` | `OCC_INCIDENT_HORIZON` |
| `smb` | `LOG_SMB_FILE_OPEN` | `OCC_INCIDENT_HORIZON` |
| `host-portscan` | `LOG_PORT_SYN` to `OCC_SCAN_HOST_THRESHOLD` distinct `dst_port`s per `src_host`/`dst_host`; the window is cleared after firing | `OCC_SCAN_HOST_HORIZON` |
| `network-portscan` | `LOG_PORT_SYN` from the same `src_host`/`dst_port` against `OCC_SCAN_NETWORK_THRESHOLD` distinct canaries (`reported_dst_host` fallback) | `OCC_SCAN_NETWORK_HORIZON` |

Each rule resolves its merge horizon through `Settings.horizon_for()`:
`OCC_INCIDENT_HORIZONS[<incident name>]` when configured, otherwise the global
`OCC_INCIDENT_HORIZON`. The legacy `<type>.incident_horizon`,
`smb.file_open_horizon` and `scans.*_horizon` keys are migrated into that map, so
per-type windows survive an upgrade.

Incident keys and descriptions are byte-compatible with the Python 2 release
(`incident:ftplogin:10.0.0.5:1418997029`, `FTP Login Attempt by … on …`), and the
report formatters keep the legacy wording.

## Redis state

| Key | Type | Purpose | TTL |
|---|---|---|---|
| `incident:<prefix><src_host>:<ts>` | hash | incident fields (`events_list` CSV of epochs, `events_count`, `acknowledged`, `notified`, `updated`, `description`, `logdata` JSON) | none |
| `incidents` | ZSET | incident index, score = last update | none |
| `scan:host:<src_host>:<dst_host>` | set | distinct scanned ports | `OCC_SCAN_HOST_HORIZON` |
| `scan:network:<src_host>:<dst_port>:targets` | set | distinct canaries hit | `OCC_SCAN_NETWORK_HORIZON` |
| `dedup:<sha256>` | string | processed-event marker | `OCC_DEDUP_TTL` |
| `incident-lock:<incident>:<src_host>` | string | create-or-merge lock | 5 s |
| `ratelimit:event:<node_id>` | counter | per-node event budget | 60 s |
| `ratelimit:connection:<ip>` | counter | per-IP connection budget | 60 s |
| `breaker:<channel>:failures` / `:open` | counter / string | shared circuit breaker | cooldown (60 s) |
| `device:<sha256(node_id)[:12]>` | hash | device metadata read by the legacy console | none |
| `logs` | list | console log lines, newest first | trimmed to 1000 |
| `console-setting:<name>` | string | console settings preserved from the legacy release | none |

Nothing enumerates keys (`KEYS`, `SCAN`, `FLUSHDB` are never used), so Redis
Cluster-safe key access patterns are preserved. Multi-step writes use
`MULTI`/`EXEC` pipelines.

## Failure semantics

| Failure | Behaviour |
|---|---|
| Malformed or oversized event | rejected, audited, connection survives (oversized closes it) |
| Redis down at startup | `startup_failed` audit, exit code 1 |
| Redis error during event handling | the event is dropped and audited; the receiver stays up |
| Rule exception | `rule_failed`, other rules still run |
| Dispatcher timeout/error | `alert_dispatch` error, other channels still receive the incident |
| Dispatcher endpoint down | retries, then the breaker opens for all replicas for 60 s |
| Lock not acquired within 5 s | `incident_lock_timeout`, no duplicate write |
| Shutdown (SIGINT/SIGTERM) | receivers stop accepting, queues drain for up to 5 s, health listener closes, clients and Redis pool close, `shutdown` audit |

## Security hardening

- Every network payload passes Pydantic validation and bounded `logdata` checks
  before touching Redis.
- Line size, connection count, queue size, event rate and delivery time are all
  bounded; a slowloris client can hold a socket but never memory or the loop.
- Audit output redacts keys matching `password|secret|token|api_key|auth|
  credential|private_key` and strips CR/LF/NUL, so honeypot data cannot forge
  audit lines or leak captured credentials.
- Redis URLs are masked in logs and `--check-config` output.
- Webhook/Slack/Discord URLs must be `http(s)`; Telegram, SMTP credentials and
  Redis passwords are held in `SecretStr` and never appear in `repr()`.
- The container runs as an unprivileged user with no build toolchain.

## Extending

- **New alert channel** — subclass `BaseDispatcher`, render the incident with
  `format_title()/format_report()/format_report_short()`, return
  `DispatchResult` (never raise), register it in `build_dispatchers`.
- **New source** — subclass `BaseReceiver` and hand validated `CanaryEvent`s to
  an `EventPipeline`; the engine needs no change.
- **New rule** — subclass `Rule` (`matches`, `apply`), append it in
  `build_rules()` in `core/rules/__init__.py`; incidents are created through
  `IncidentRepository.record()` so locking, merging and dedup stay consistent.
