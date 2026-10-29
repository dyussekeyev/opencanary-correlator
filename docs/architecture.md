# Architecture

The correlator turns a stream of independent honeypot events into a small number
of incidents and delivered alerts. It is a single asyncio process with no
in-process correlation state, so any number of replicas can run behind a load
balancer.

## Runtime topology

```
 canary nodes                    correlator replica                 external
┌────────────┐  TCP 15140   ┌──────────────────────────┐          ┌──────────┐
│opencanaryd │─────────────▶│ TCPJSONReceiver          │          │  Redis   │
│ SocketJSON │              │  line framer → Pydantic  │─────────▶│ windows  │
│  Handler   │              │  → per-host lanes        │          │ incidents│
└────────────┘              │  → rate limiter          │          │ locks    │
                            │        │                 │          │ dedup    │
┌────────────┐  TCP/UDP     │        ▼                 │          │ breaker  │
│ SysLog     │ 15141        │ CorrelationEngine        │          └──────────┘
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

`--health-port` adds a tiny HTTP listener (`/healthz`, `/readyz`, `/metrics`) for
probes and Prometheus scraping. It binds every interface by default and follows
`OCC_HEALTH_HOST` when the operator wants it on loopback only; the endpoint is
unauthenticated, so a wildcard binding should be firewalled or fronted by the
network policy. Configuration is read once at startup; every credential comes
from the environment or `.env`.

The two event receivers are the opposite case: they bind `127.0.0.1` by default,
because the correlator usually shares a host with its canary and every listener
here accepts unauthenticated events. Remote canaries set `OCC_TCP_HOST` /
`OCC_SYSLOG_HOST`. All three ports sit in an uncommon block (`15140` TCP JSON,
`15141` syslog, `15142` health) so they cannot collide with the services a
honeypot imitates — notably `8080`, the classic HTTP-alt port.

## Package map

| Path | Responsibility |
|---|---|
| `config.py` | `Settings` (pydantic-settings, `OCC_` prefix), legacy `.conf` importer; wires field validators |
| `config_validation.py` | pure validation rules for `Settings` (URL, port and bound checks), no state and no environment access |
| `enrichment/` | optional attacker-IP context: `geo.py` reads DB-IP/GeoLite2 MMDB files offline, `virustotal.py` adds the VirusTotal verdict behind a Redis cache and three quota windows, `service.py` bounds the whole pass |
| `schemas.py` | `CanaryEvent` (lenient, bounded), typed `logdata` accessors, `IncidentRecord` |
| `constants.py` | `LogType` registry, incident key prefixes, legacy Redis key names, defaults |
| `redaction.py` | secret masking and control-character stripping for audit output |
| `audit.py` | `AuditEvent`/`AuditLogger` JSON lines, `RedisLogHandler` for the bounded console log |
| `log_setup.py` | root logger level, stderr handler and the optional size-rotated `OCC_LOG_FILE` handler; raises `LogSetupError` when the file cannot be opened |
| `connectors/base.py` | `EventSink`, `RateLimiter`, `BaseReceiver`, `BaseDispatcher`, `DispatchResult` — the only types `core` may import |
| `connectors/receivers/_base.py` | `NetworkReceiver`: shared scaffolding for TCP and UDP receivers (pipeline, counters, bound port, audit) |
| `connectors/receivers/_stream.py` | per-connection protocol: framing loop, 64 KiB cap, partial-line timeout, TCP keep-alive |
| `connectors/receivers/_tcp.py` | listening side: server socket, connection cap, admission, payload dispatch to the pipeline |
| `connectors/receivers/_framing.py` | RFC 6587 framing as pure functions: newline/NUL split, octet counting, overflow |
| `connectors/receivers/_pipeline.py` | bounded queue, per-host consumer lanes, rate limiting, audit, counters |
| `connectors/receivers/tcp_json.py` | `SocketJSONHandler` compatibility: newline-delimited JSON, `[ERR]` tolerance |
| `connectors/receivers/_syslog_codec.py` | RFC 3164/5424 envelope parser and event construction, no transport |
| `connectors/receivers/syslog.py` | the syslog TCP and UDP transports; framing modes and the newline fallback |
| `connectors/dispatchers/base.py` | HTTP client ownership, retry policy, `Retry-After`, per-endpoint Redis circuit breaker |
| `connectors/dispatchers/*.py` | webhook, Slack, Telegram, Discord, SMTP channels |
| `core/windows.py` | sliding window (ZSET), fixed-TTL distinct-set window (port scans), dedup cache, event fingerprint |
| `core/rules/` | `LoginRule` (14 log types), `SmbFileOpenRule`, host/network port-scan rules |
| `incident_specs.py` | one declarative row per incident type (name, class name, key prefix, description); `INCIDENT_TYPES` and `constants.INCIDENT_KEY_PREFIX` are derived from it |
| `core/incident_base.py` | `Incident` base: Redis hash fields, logdata merge and truncation rules, report defaults |
| `core/incident_model.py` | the four types with custom logic, the generated subclasses and the type registry |
| `core/logdata.py` | the single `logdata` decoder shared by the alert renderer and the incident model |
| `core/incident_report.py` | legacy plain-text alert templates (title, full, short and scan reports), pure functions |
| `core/incident.py` | `IncidentRepository`: atomic create-or-merge in Redis; re-exports the model names |
| `core/engine.py` | dedup → rule routing → dispatcher fan-out with per-channel timeout |
| `storage/keys.py` | byte-compatible legacy Redis key builders |
| `storage/scripts.py` | Lua bodies for the incident write and lock release, each run as one atomic round trip |
| `storage/_base.py` | client ownership, script registration, reply normalisation (bytes or text clients), plain key and hash/set/ZSET reads |
| `storage/_dedup.py` | first-writer-wins event fingerprints |
| `storage/_windows.py` | set, ZSET and counter windows whose expiry is written once |
| `storage/_quota.py` | atomic multi-window reservations for a rate-limited provider |
| `storage/_cache.py` | string values, used by the enrichment cache |
| `storage/_console.py` | the bounded legacy console journal |
| `storage/_incidents.py` | incident hash, index pointer and the capped lookup scan |
| `storage/_locks.py` | the distributed lock and its defaults |
| `storage/redis_store.py` | `RedisStore`, a composition of the mixins above; no method bodies of its own |
| `storage/queries.py` | async read side with the console JSON shape (`created_printable`, `events_list`, …) |
| `storage/rate_limit.py` | per-IP connection and per-node event budgets |
| `metrics.py` | Prometheus counters/gauges and text exposition |
| `health.py` | `/healthz` and `/readyz` with a Redis ping; `/metrics` without one |
| `app/parser.py` | flags, `load_settings`, `CorrelatorStartupError` |
| `app/channels.py` | `CHANNEL_SPECS`, the one table `--check-config` and startup both read; `build_dispatchers` |
| `app/wiring.py` | enricher, receivers, rate limiter, health server |
| `app/describe.py` | the secret-free `--check-config` document and the values `log_secrets` masks |
| `app/runner.py` | supervision, signal handling, `main` and the exit codes |
| `cli.py` | a 39-line façade re-exporting the `app` package, the documented import path |

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
3. **Queue** — the event enters one of `OCC_EVENT_CONCURRENCY` bounded lanes
   (default 8) chosen by a CRC of `src_host`; the `OCC_EVENT_QUEUE_SIZE` budget
   is split between them. On overflow the event is dropped and audited as
   `event_dropped`; the receiver never blocks the event loop. Sharding by host
   keeps every event from one host in arrival order — so incident merging stays
   deterministic — while different hosts are correlated in parallel and one slow
   host or dispatcher cannot stall the rest.
4. **Rate limit** — each lane asks `RedisRateLimiter` for an event
   budget per `node_id` (`OCC_RATE_LIMIT_EVENTS_PER_MINUTE`, `0` disables).
   Budgets use a fixed window whose expiry is written when the counter is
   created and never refreshed, so sustained traffic cannot extend it.
   Over-budget events are audited as `event_rate_limited`.
5. **Dedup** — `event_fingerprint` hashes
   `node_id|src_host|src_port|dst_host|dst_port|logtype|logdata` with SHA-256;
   `SET NX PX` on `dedup:<fingerprint>` rejects retransmits, audited as
   `event_deduplicated`. The claim is a **lease** (`OCC_DEDUP_LEASE`, 10 s) while
   the rules run, and is extended to the full window (`OCC_DEDUP_TTL`) only by a
   Lua compare-and-expire once the event is stored, so a process that dies
   mid-correlation cannot suppress the canary's redelivery. A rule failure
   releases the claim; a lease that expired before the confirm is recorded as
   `event_dedup_lease_lost`.
6. **Route** — every rule is asked `matches(event)`, then `apply(event, now)`.
   A rule raising is audited as `rule_failed` and does not stop the others. If
   no rule matched, a node-lifecycle `logtype` (boot, base message, ping, …) is
   audited as `event_ignored` at INFO, and anything else as `event_unrouted` at
   WARNING — the distinction keeps expected chatter out of the warning stream
   while a genuinely new `logtype` still shows up there.
7. **Create or merge** — `IncidentRepository.record()` takes
   `incident-lock:<incident>:<src_host>` (5 s TTL) and looks for a live incident
   with the same incident type and exact `src_host` segment (the lookup
   includes the `:` key boundary, so `10.0.0.5` never matches `10.0.0.55`)
   inside the horizon. The lookup is served from
   `incident-latest:<incident>:<src_host>`, a small hash holding the newest
   incident key and its score for that host, instead of scanning the whole
   `incidents` ZSET; it falls back to the index scan when the pointer is
   missing, points outside the horizon, or points at a deleted incident, so
   older replicas stay correct during a rolling upgrade. That scan reads at most
   `OCC_INCIDENT_LOOKUP_SCAN_LIMIT` members (`ZREVRANGEBYSCORE … LIMIT 0 N`,
   default 100), newest first. A capped miss is not trusted: the whole horizon
   window is read once, so a live incident behind the cap is merged rather than
   duplicated. That full read runs only for a host with no pointer and no match,
   and it creates the pointer for later events.
   The incident is then merged (`events_count += 1`, append timestamp, merge
   `logdata`) or created, and one Lua script writes the hash, the ZSET entry and
   the pointer atomically. Only creation returns an incident for delivery; a
   merge deliberately produces no alert. A merge into an incident whose history
   is already full at `OCC_MAX_STORED_EVENTS` writes the counters only, and skips
   the timestamp append and the stored-history decode entirely, because both
   would return the stored value unchanged (see `docs/validation.md`). Scan
   incidents are exempt: their `logdata` is a deduplicated set that must stay
   exact.
8. **Deliver** — an incident is created together with one outbox entry per
   channel in the same Lua script, so the decision to notify cannot exist
   without a record of it. The engine then fans out inline, each attempt bounded
   by `OCC_DISPATCH_TIMEOUT`; a timeout, exception or non-success result is
   audited as `alert_dispatch` with status `error`, other channels are
   unaffected, and ingestion continues immediately.
9. **Retry** — the entry of a failed attempt stays in `outbox:alerts` (a ZSET
   scored by its next attempt). Every replica runs one worker: it claims what is
   due (the claim pushes the score forward by `OCC_OUTBOX_LEASE`, so two
   replicas never take the same entry and a dying worker leaves it to become due
   again), reloads the incident, delivers, and either settles the entry — a
   `outbox:delivered:<id>` marker plus a delete, in one script — reschedules it
   with backoff (`1 s, 5 s, 30 s, 5 min, 30 min`, audited as `alert_retry`) or
   buries it in `outbox:dead` after `OCC_OUTBOX_MAX_ATTEMPTS` (audited as
   `alert_dead_letter`). Delivery is therefore **at-least-once**: a duplicate is
   possible only when a channel accepted a message and the process died before
   settling it. `OCC_OUTBOX_ENABLED=false` restores best-effort delivery, where a
   failure is logged and forgotten.
10. **Ration (optional)** — with `OCC_ALERT_BUDGET_ENABLED=true`, step 8 asks the
    budget before the first attempt. `budget:node:<window>:<node>` and
    `budget:global:<window>` are fixed-window counters reserved by one Lua
    script, so replicas share a single budget and scaling out does not multiply
    it. Over the limit, the notification is withheld — the incident stays stored
    and visible — its outbox entries are withdrawn in one script so nothing
    retries them later, and `alert_suppressed` records the refusal. The refusal
    is counted in `budget:suppressed:<window>` in the same reservation, and the
    summary worker every replica runs sends it once, to whoever removes the
    member from `budget:summaries` first, as a plain-text `alert_summary` through
    each channel's notice path (Telegram, Slack, Discord, SMTP; the generic
    webhook declines, because a SIEM would index the summary as an alert). A
    budget that cannot count fails open: the alert is sent and
    `alert_budget_failed` is audited.

## Service messages

A second, much smaller path runs beside delivery: the correlator's report about
itself. It is off by default (`OCC_SERVICE_ENABLED`) and never touches the event
hot path — the call sites are the failure branches that already write an audit
record, the dispatch result, and process start/stop.

| Source | Kinds | Where it is noticed |
|---|---|---|
| Enrichment | `enrichment.virustotal.key_rejected`, `…quota`, `…unavailable`, `enrichment.geo.unavailable` | `enrichment/service.py`, on the branches that already emit `enrichment_failed` / `enrichment_skipped` |
| Channels | `channel.circuit_open`, `channel.all_failing` | `core/engine.py`, from the dispatch result (a skipped `circuit_open` attempt, or `ALL_CHANNELS_FAILING_THRESHOLD` consecutive alerts nobody accepted) |
| Lifecycle | `lifecycle.started`, `lifecycle.stopped` | `app/runner.py`, around the supervised task set |

`ServiceNotifier` applies three gates before anything is sent: the category
(`OCC_SERVICE_CATEGORIES`), the severity floor (`OCC_SERVICE_MIN_SEVERITY`) and a
suppression slot per `(kind, subject)`. The slot is one Lua script
(`SERVICE_MESSAGE_SLOT_LUA`): `SET NX EX <cooldown>` admits the first occurrence,
and every refusal increments a counter that the next admitted message reports as
its repeat count. Two replicas therefore cannot both announce the same
degradation, and a broken dependency that fails on every alert becomes one
message per `OCC_SERVICE_COOLDOWN` rather than a storm.

Delivery reuses the configured dispatchers, each with its own `notify()` method
(the default raises, so a new channel cannot silently swallow these). Routing is
by name (`OCC_SERVICE_CHANNELS`, empty means all), and a name that matches no
configured channel is a startup error. The payload carries no incident key and no
attacker data: the generic webhook sends `{kind, severity, title, text, count}`,
which a SIEM can route without matching an alert rule.

## Background tasks

Two tasks run beside the receivers and the outbox worker, in the same supervised
start/stop sequence (`app/runner.py`):

| Task | Cadence | State |
|---|---|---|
| `stats` (`core/stats.py`) | every 60 s | hash `stats:instance:<uuid>`, TTL 300 s, counters read from the process-local Prometheus registry |
| `digest` (`core/digest.py`) | once a day at `OCC_DIGEST_TIME` | lock `digest:lock:<date>` plus marker `digest:sent:<date>` |

The heartbeat is why the digest is cheap: no Redis write happens per event, and a
replica that dies stops contributing when its hash expires. `collect_digest` sums
the live hashes, counts the incidents in the trailing 24 h from the `incidents`
ZSET and ranks the sources by parsing the incident keys. The scheduler sleeps on
its stop event in at most 60 s slices, so a clock jump or a changed time is
picked up quickly, and the day marker is written only after a channel accepted
the message — a crash mid-send can replay the digest once, which is better than
losing the day.

## Correlation rules

| Rule | Trigger | Horizon |
|---|---|---|
| `login` | `LOG_FTP_*`, `LOG_HTTP_POST_LOGIN_ATTEMPT`, `LOG_SSH_LOGIN_ATTEMPT`, `LOG_TELNET_LOGIN_ATTEMPT`, `LOG_HTTPPROXY_LOGIN_ATTEMPT`, `LOG_MYSQL_LOGIN_ATTEMPT`, `LOG_MSSQL_LOGIN_SQLAUTH`, `LOG_MSSQL_LOGIN_WINAUTH`, `LOG_TFTP`, `LOG_NTP_MONLIST`, `LOG_VNC`, `LOG_SNMP_CMD`, `LOG_RDP`, `LOG_SIP_REQUEST`, `LOG_MONGODB_LOGIN_ATTEMPT` | `OCC_INCIDENT_HORIZON` |
| `smb` | `LOG_SMB_FILE_OPEN`, except actions in `OCC_SMB_IGNORE_ACTIONS` | `OCC_INCIDENT_HORIZON` |
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

**Stored history is bounded.** A merged incident appends one epoch to the
`events_list` CSV and one entry to `logdata`, and both stop growing at
`OCC_MAX_STORED_EVENTS` (default `100`, matching what the console renders). They
are frozen rather than trimmed, so the oldest entries stay byte-identical for the
console, and once an incident is full the merge writes only `events_count`,
`events_truncated` and `updated` instead of re-serialising the whole hash. That
is what keeps the cost of an event independent of the size of the incident:
before the cap, 10,000 events from one host rewrote a growing half-megabyte hash
on every event and took 77 s.

`events_count` is always exact, so the console keeps the true size of the
incident; `events_truncated=true` marks the stored history as partial, and
`events_skipped` in the console payload is derived from the counter (with a
fallback to the stored list length for incidents written before the field
existed). Scan incidents are exempt by design: `scans.host_portscan` stores
distinct ports and `scans.network_portscan` distinct targets, one entry per
member rather than per event, so their lists are bounded by the port universe
and truncating them would delete the evidence the incident exists to record.

## Redis state

| Key | Type | Purpose | TTL |
|---|---|---|---|
| `incident:<prefix><src_host>:<ts>` | hash | incident fields (`events_list` CSV of epochs and `logdata` JSON, both capped at `OCC_MAX_STORED_EVENTS`; `events_count`, `events_truncated`, `acknowledged`, `notified`, `updated`, `description`) | none |
| `incidents` | ZSET | incident index, score = last update | none |
| `scan:host:<src_host>:<dst_host>` | set | distinct scanned ports | `OCC_SCAN_HOST_HORIZON`, fixed at creation |
| `scan:network:<src_host>:<dst_port>:targets` | set | distinct canaries hit | `OCC_SCAN_NETWORK_HORIZON`, fixed at creation |
| `dedup:<sha256>` | string | processed-event marker | `OCC_DEDUP_TTL` |
| `incident-lock:<incident>:<src_host>` | string | create-or-merge lock | 5 s |
| `incident-latest:<incident>:<src_host>` | hash | newest incident key + score for that host (internal O(1) lookup) | none |
| `ratelimit:event:<node_id>` | counter | per-node event budget | 60 s |
| `ratelimit:connection:<ip>` | counter | per-IP connection budget | 60 s |
| `breaker:<channel>:<endpoint-hash>:failures` / `:open` | counter / string | per-endpoint circuit breaker, shared across replicas | cooldown (60 s) |
| `device:<sha256(node_id)[:12]>` | hash | device metadata read by the legacy console | none |
| `logs` | list | console log lines, newest first | trimmed to 1000 |
| `console-setting:<name>` | string | console settings preserved from the legacy release | none |

Nothing enumerates keys (`KEYS`, `SCAN`, `FLUSHDB` are never used). Multi-step
writes use `MULTI`/`EXEC` pipelines, and the incident write plus the lock
release are Lua scripts, so they stay atomic in one round trip. A merge into a
full incident sends three fields (`events_count`, `events_truncated`, `updated`)
instead of the whole hash, which is why a busy incident stops costing more per
event than an idle one, and why a full-field replication on every write is no
longer the dominant cost.

**Redis topology: one logical server, not Redis Cluster.** `save_incident()`
writes an `incident:*` hash, the `incidents` ZSET and the host pointer in one
script. In a Redis Cluster those keys hash to different slots, so the script
fails with `CROSSSLOT`. The legacy key layout cannot be hash-tagged without
breaking the console, so Cluster support is explicitly out of scope. A
primary/replica setup, or a single failover endpoint/VIP, is supported;
correlator replicas still scale horizontally against that one Redis. Scripting
must be enabled, which it is on every Redis release covered by the deployment
target (2.6 and newer, including managed Redis and Redis-compatible servers).

## Metrics

`GET /metrics` on the health listener exposes the Prometheus text format from
`opencanary_correlator.metrics`. The counters are process-local: every replica
is scraped separately, which is the normal Prometheus model for a horizontally
scaled service. No metric carries an incident key, source address, payload or
credential; labels are limited to receiver name, result/reason, rule name and
dispatcher name.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `opencanary_events_total` | counter | `result` (`accepted`, `rejected`, `dropped`, `rate_limited`, `deduplicated`, `unrouted`) | event outcomes across ingestion and correlation |
| `opencanary_events_dropped_total` | counter | `reason` (`queue_full`, `dispatch_failed`, `shutdown`) | events lost before correlation, split by cause |
| `opencanary_event_queue_depth` | gauge | — | events waiting across the pipeline lanes |
| `opencanary_active_connections` | gauge | `receiver` | currently open receiver connections |
| `opencanary_connection_rejections_total` | counter | `receiver`, `reason` | rejected connections before payload processing |
| `opencanary_rule_failures_total` | counter | `rule` | isolated rule exceptions |
| `opencanary_alerts_total` | counter | `dispatcher`, `status` | alert delivery attempts by outcome |
| `opencanary_outbox_pending` | gauge | — | deliveries waiting for a retry |
| `opencanary_outbox_delivered_total` | counter | `channel` | deliveries settled as accepted |
| `opencanary_outbox_retried_total` | counter | `channel` | deliveries rescheduled for another attempt |
| `opencanary_outbox_dead_total` | counter | `channel` | deliveries buried in the dead letter list |
| `opencanary_alerts_budget_total` | counter | `result` (`allowed`, `suppressed`) | notifications the alert budget rationed |
| `opencanary_build_info` | info | `version`, `python` | static build information |

The endpoint never pings Redis, so it remains scrapeable during a Redis failure;
use `/readyz` for dependency health. Disabling `OCC_HEALTH_PORT` disables both
health and metrics, and `OCC_HEALTH_HOST` chooses the interface they listen on
(`0.0.0.0` by default, `127.0.0.1`/`::1` for loopback-only).

## Failure semantics

| Failure | Behaviour |
|---|---|
| Malformed or oversized event | rejected, audited, connection survives (oversized closes it) |
| Redis down at startup | `startup_failed` audit, exit code 1 |
| Redis error during event handling | the event is dropped and audited; the receiver stays up |
| Rule exception | `rule_failed`, other rules still run |
| Dispatcher timeout/error | `alert_dispatch` error, other channels still receive the incident |
| Dispatcher endpoint down | retries, then that endpoint's breaker opens for all replicas for 60 s; the other URLs/chats of the same channel keep delivering |
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
- Every log sink — stderr, `OCC_LOG_FILE` and the legacy console journal — is
  treated as hostile territory. Records are flattened (C0 controls, DEL,
  U+0085/U+2028/U+2029, which several collectors treat as line breaks) and
  secrets are masked twice: at record level for handlers that format on their
  own, and again in the formatter so `exc_info` tracebacks are covered. Masked
  values are the configured endpoint URLs and tokens by exact match, plus
  `api.telegram.org/bot<token>`, Slack/Discord webhook paths, `?token=`/
  `?api_key=`-style query parameters and `scheme://user:pass@`.
- Incident `logdata` is never logged raw: it can hold a password the canary
  captured. Fallback branches log the incident key instead.
- Redis URLs are masked in logs and `--check-config` output.
- Webhook/Slack/Discord URLs must be `http(s)`; Telegram, SMTP credentials and
  Redis passwords are held in `SecretStr` and never appear in `repr()`. The URL
  list fields are `repr=False` for the same reason, and configuration errors name
  the list position and host rather than echoing the URL.
- SMTP supports both STARTTLS (`OCC_SMTP_STARTTLS`, port 587) and implicit TLS
  (`OCC_SMTP_USE_TLS`, port 465); enabling both is rejected at startup.
- Prometheus labels are fixed and low-cardinality; incident keys, source
  addresses and payload contents are never exported.
- The container runs as an unprivileged user with no build toolchain, on
  digest-pinned base images, installing the hash-locked dependency graph.
- **Accepted limitation: intake traffic is not encrypted.** The stock OpenCanary
  `SocketHandler`/`SyslogHandler` has no TLS, so the receivers accept plaintext
  JSON by design. Operators who need confidentiality or integrity on that path
  wrap it in an SSH forward, WireGuard or IPsec tunnel they run themselves. See
  the README's *Transport limitation* section for the configurations.

## Extending

- **New alert channel** — subclass `BaseDispatcher`, render the incident with
  `format_title()/format_report()/format_report_short()`, return
  `DispatchResult` (never raise), register it in `build_dispatchers`.
- **New source** — subclass `BaseReceiver` and hand validated `CanaryEvent`s to
  an `EventPipeline`; the engine needs no change.
- **New rule** — subclass `Rule` (`matches`, `apply`), append it in
  `build_rules()` in `core/rules/__init__.py`; incidents are created through
  `IncidentRepository.record()` so locking, merging and dedup stay consistent.
- **New log line or channel** — treat every log statement as a potential secret
  sink: never log `logdata`, settings objects or raw URLs; put new configured
  secrets into `cli.log_secrets()` so the exact-match redaction covers them, and
  add the value to `tests/unit/test_secret_leaks.py`, which fails if a secret
  appears in the log file, on stderr or in a delivered message.
