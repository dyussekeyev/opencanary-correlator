# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Changed — docs

- `docs/validation.md` is refreshed against the 0.4.0 release run (`e7337fd`,
  run 40769958410): 780 tests at 96.65 % coverage, the CI jobs actually in use
  — Windows and the native benchmark included — the 90 % floor on
  `core`/`storage`/`connectors/receivers`, and `pip-audit` in the lint gate.
  The 2026-10-24 snapshot stays as dated history instead of being deleted.
- The `[0.4.0]` heading is dated by the release's UTC publish time
  (`2026-10-28`), so it matches the GitHub release page and `[0.3.2]`.

## [0.4.0] - 2026-10-28

This release changes defaults: the intake listens on loopback and the default
ports differ. Read [Changed — breaking](#changed--breaking) before upgrading, or
set the old values explicitly to keep the previous layout.

### Added

- Optional attacker-IP enrichment in the alert. `OCC_GEOIP_CITY_DB` /
  `OCC_GEOIP_ASN_DB` read DB-IP Lite or GeoLite2 MMDB files locally, so country,
  city and ASN work without a key, a quota or sending the address anywhere; the
  reader is the new `geo` extra (`pip install "opencanary-correlator[geo]"`,
  included in the image). Private and invalid addresses are skipped, and a
  configured database that cannot be opened stops startup.
- `OCC_VIRUSTOTAL_API_KEY` adds the VirusTotal detection ratio and reputation.
  Off by default; setting the key is also the consent to disclose attacker
  addresses to a third party. The free-tier limits (4/min, 500/day, 15.5K/month)
  are enforced through one atomic Redis reservation before every request, and a
  verdict is cached per address for `OCC_VIRUSTOTAL_CACHE_TTL` (7 days), so
  repeated attacks cost one lookup. An exhausted window renders
  `VT: quota exhausted`, an error `VT: unavailable`, and the alert is always
  delivered.
- `minimal` alerts are unchanged; `standard` adds country and the detection
  ratio, `detailed` adds city, network and VirusTotal's reputation and analysis
  date. `docker-compose.yml` mounts an optional read-only `./geoip` directory.
- The JSON webhook carries the same context as an `enrichment` object at every
  detail level: country, city, ASN and AS organisation plus the VirusTotal verdict
  with derived `detections` and `total`, or `virustotal_status` when a provider was
  asked but returned no verdict. `text` is untouched at the default `minimal`
  level and an unconfigured deployment POSTs the same three keys as before, so a
  SIEM pipeline gets indexable fields without a parser change.

- `http.request` incidents. OpenCanary logs a plain `GET` as `3000`, an
  unsupported method as `3002` and a redirect as `3003`; all three were audited
  as `event_unrouted` and dropped. They now create one incident type
  (`incident:httprequest:<src_host>:<ts>`) whose alert shows the method, path,
  virtual host and user agent. Login attempts on `3001` keep their separate
  `http.login_attempt` incident. `http.request` is a valid key for
  `OCC_INCIDENT_HORIZONS`.
- `OCC_TCP_PUBLISH_HOST` and `OCC_SYSLOG_PUBLISH_HOST` set the host side of the
  compose port mapping, defaulting to `127.0.0.1`.
- [docs/opencanary-side.md](docs/opencanary-side.md) documents the two
  honeypot-side problems a deployment hits — `SocketJSONHandler` losing the first
  record and not reconnecting after a correlator restart, and a `twistd.pid`
  that survives a container restart — with a tested reconnect handler and the
  three ways to stop the PID file blocking startup.
- A peer that closes its intake connection is audited as `connection_closed`
  with `reason: peer_closed` at INFO. That is the moment a canary stops
  delivering, and the correlator cannot ask it to reconnect: the audit record
  makes the gap visible instead of leaving a silent drop.

### Fixed

- A log field whose key names a credential is now masked in alerts by the same
  rule the audit trail uses. The renderer kept its own list, which lacked
  `credential`, so `CREDENTIAL=...` appeared in every chat channel, the e-mail
  body and the webhook while the audit record for the same event hid it. One
  list, one sanitiser and one `logdata` decoder now serve both paths.
- A credential captured one level down in `logdata` is masked too. The login
  rules store the captured event as `{"raw": [{"PASSWORD": ...}]}`, and the
  renderer decided by the outer key alone, so every RDP, SSH and Telnet alert
  printed the password the honeypot recorded. Nested values now go through the
  same redaction, and the `raw` wrapper is unwrapped, so the line reads
  `USERNAME=administrator, PASSWORD=***` instead of a JSON blob.
- `OCC_LOG_LEVEL=DEBUG` no longer opens `httpx`, `httpcore`, `h11` and `hpack`.
  `httpx` logs every request URL at INFO — the Telegram Bot API keeps its token
  in the URL path — and the other three log connection and frame details at
  DEBUG, so a debug session wrote network internals to stderr and the rotated
  log file. They are capped at `WARNING` at startup; their real failures are
  still logged and still redacted.
- Node lifecycle `logtype` values (`1000` boot, `1001` base message, `1002`
  debug, `1003` error, `1004` ping, `1005` config save, `1006` example) are
  audited as `event_ignored` at INFO instead of `event_unrouted` at WARNING.
  A plain-text syslog body becomes `1001`, so ordinary `opencanaryd` output no
  longer fills the warning stream; a genuinely unrouted type still does.
- The Redis client now has a 5 s command timeout, a 5 s connect timeout and a
  30 s idle health check (`RedisStore.from_url` also takes them as arguments).
  A Redis that accepted the connection and then stopped answering used to hang
  every `await` forever: ingestion, the health probe and alert delivery share one
  event loop, so the process stopped serving with nothing in the log to say why.
  A stalled command now fails, is audited, and leaves the process responsive.
- A circuit breaker that cannot read its own state no longer decides delivery.
  Breaker state lives in Redis, and `allow()` raising there refused a healthy
  channel, while a failed `record_success()` reported a delivered alert as an
  error. Breaker failures are logged at WARNING and the delivery proceeds; the
  reported outcome is always the HTTP outcome.
- A sender that packs several frames into one TCP segment and then exceeds the
  line limit no longer loses the earlier frames: they were parsed, removed from
  the buffer and dropped together with the hostile one.
- The single-incident read returns `None` for a stored hash it cannot render
  instead of raising. The listing already skipped and logged such a record, so
  one corrupt field used to break the detail view while the list worked.
- `OCC_VIRUSTOTAL_API_KEY` is part of the log redaction list. It travels in a
  header, which `httpx` does not log, but an exception carrying the request
  would have printed it.
- A legacy `.conf` import now reaches the same mail relay as the Python 2
  notifier did. The old code opened `smtplib.SMTP(server, 25)` with no STARTTLS,
  while an import inherited the modern `587` + STARTTLS defaults: a plain relay
  answered with an error and the alert was lost. `from_legacy_json` starts from
  plain SMTP on port 25, a `console.email_port` in the file still wins, and the
  environment/CLI surface keeps the modern defaults.
- The CLI accepts `-c` and `-i` again, the flags the Python 2 executable took
  (`twistd` options). `-i/--ip` sets the intake interface for both receivers, so
  an existing unit file or wrapper runs unchanged instead of failing on an
  unrecognised argument.
- The partial-line deadline now runs from the first byte of an incomplete line
  instead of restarting on every chunk. Re-arming it per chunk made it an idle
  timeout, so a peer sending one byte just before each expiry held a connection
  slot indefinitely; with `OCC_MAX_CONNECTIONS` slots taken, the intake stopped
  accepting canaries. A silent `SocketJSONHandler` keep-alive buffers nothing and
  is still never reaped, and a line that really is stalled is closed exactly as
  before.
- An event whose correlation raised no longer stays deduplicated for the whole
  window. The claim is taken before the rules run, so one `rule_failed` (a Redis
  hiccup inside a rule, a persistence error) used to answer the redelivery of the
  very same event — a second syslog relay, a canary that reconnects — with
  `event_deduplicated` while nothing had been stored. The claim is now withdrawn
  when any rule failed, so the retry can correlate.
- The health listener serves at most 128 requests at a time and answers `503`
  beyond that. It binds every interface by default and is unauthenticated, and
  each accepted socket held a task until its request completed, so one peer
  opening sockets it never finished could exhaust the process file descriptors —
  stalling the very probe that is meant to report an unhealthy process. A
  refused peer that does send a well-formed request still receives the `503`,
  and the refusal is audited as `health_request_rejected` with reason
  `too_many_requests`.

### Fixed — internal

- `TCPStreamReceiver` and `SyslogUDPReceiver` default to `127.0.0.1` instead of
  `0.0.0.0`. `app.wiring` always passes the configured host, so no deployment
  changes; the wildcard default was a footgun for any other caller, because both
  listeners accept unauthenticated writes.
- `RedisStore` now normalises every reply, so a client built with
  `decode_responses=False` reads the same values as the production client.
  Before, `get_value` answered `None` for such a client (the enrichment cache
  silently never hit) and `hgetall`/`smembers`/`lrange` answered `"b'...'"`.
  `RedisStore.from_url` already decoded, so a deployment is unaffected.

### Changed

- `OCC_SMTP_DETAIL` defaults to `standard`, like the chat channels: a person
  reads the mail, and the legacy body showed none of the attacker context. Set
  `OCC_SMTP_DETAIL=minimal` to restore the old body for a mail filter that parses
  it.
- The alert layout no longer repeats the destination host. The instance address
  now carries its port (`🌐 IP: 203.0.113.7:3389`) and the separate
  `Destination` row is gone; `detailed` adds the event counter and more log
  entries under the attacker block. Applies to every channel and to `webhook` /
  `smtp` as soon as they use `standard` or `detailed`; `minimal` is unchanged.
- `OCC_SLACK_ENABLED` defaults to `false`. The old default was `true`, which
  meant `OCC_SLACK_ENABLED=true` with no `OCC_SLACK_WEBHOOKS` silently created
  no channel at all. Enabling Slack without a webhook is now a startup error,
  and a webhook with the switch off logs a warning. Deployments that set only
  `OCC_SLACK_WEBHOOKS` must add `OCC_SLACK_ENABLED=true`.

### Changed — breaking

- **Intake binds loopback by default.** `OCC_TCP_HOST` and `OCC_SYSLOG_HOST`
  default to `127.0.0.1` instead of `0.0.0.0`, and `docker compose` publishes
  `15140` and `15141` on `127.0.0.1` only. An intake port reachable from the
  network accepts unauthenticated events, and the usual deployment keeps the
  canary on the same host. Canaries on other machines need
  `OCC_TCP_HOST=0.0.0.0` (and the syslog equivalent) plus
  `OCC_TCP_PUBLISH_HOST=0.0.0.0` / `OCC_SYSLOG_PUBLISH_HOST=0.0.0.0`; the publish
  address is now a variable, so a compose update cannot widen it back.
- **Uncommon default ports.** The correlator no longer listens next to the
  services a honeypot imitates:

  | Purpose | ≤ 0.3.2 | 0.4.0 |
  |---|---|---|
  | TCP JSON intake | `1514` | `15140` |
  | Syslog TCP + UDP | `5514` | `15141` |
  | Health and `/metrics` | `8080` | `15142` |

  `8080` was the worst offender: honeypot modules emulate web services there, so
  a trap and the metrics listener competed for one port. To keep the previous
  layout, set `OCC_TCP_PORT=1514`, `OCC_SYSLOG_PORT=5514` and
  `OCC_HEALTH_PORT=8080` in `.env`; the canary's `SocketJSONHandler` port must
  match whichever value is configured.

### Changed — internal

No output changes: the same alerts, audit records, Redis keys and
`--check-config` document. The internal structure was reorganised so a change
touches one module instead of several:

- One credential list, one text sanitiser and one `logdata` decoder serve both
the audit trail and every alert channel (`redaction.py`, `core/logdata.py`).
- The incident registry is one declarative table (`incident_specs.py`); adding a
  type no longer means editing a class, a registry tuple and a key-prefix map.
  A forgotten prefix used to fail at runtime with `KeyError`.
- `cli.py` became the `app` package (`parser`, `channels`, `wiring`, `describe`,
  `runner`) with `cli.py` kept as a façade. `--check-config` and startup now read
  one `CHANNEL_SPECS` table, so a summary cannot advertise a channel that is
  never built.
- `RedisStore` is assembled from one mixin per concern (`storage/_*.py`) instead
  of one 400-line module.
- The syslog codec (`receivers/_syslog_codec.py`) and RFC 6587 framing
  (`receivers/_framing.py`) left the transports, so partial-frame and
  octet-counting behaviour is unit-tested without a socket.
- The incident base model (`core/incident_base.py`) left the type registry, and
  the per-connection protocol (`receivers/_stream.py`) left the listening side.
  No module holds more than ~300 lines now, apart from the settings schema.
- The 713-line `test_cli.py` and 685-line `test_incident.py` split along the
  same seams.
- The suite now guards the paths where a defect would hurt rather than the ones
  that merely execute: the intake's connection and per-node budgets, the codec's
  rejection reasons, the renderer's degradation cases (a corrupt timestamp, an
  empty value, a hostile proxy header), and the read side's dangling hashes and
  stale enrichment cache. Branch coverage 94.4 % → 96.8 %. `NetworkReceiver`
  exposes `pending` next to `stats` so a test can assert what reached the queue.

A golden snapshot (`tests/characterization/`) renders 75 alerts, the
`--check-config` document, the CLI help, stored incident fields and the audit and
Redis outcome of one fixed event stream, and fails on any byte that moves; it is
what backs the "no output changes" claim.

## [0.3.2] - 2026-10-28

### Added

- `OCC_LOG_FILE` writes the operational log to a size-rotated UTF-8 file
  (10 MiB × 5 backups) in addition to stderr, and `--log-file` overrides it.
  `OCC_LOG_LEVEL` now also accepts `WARN` and `FATAL`. An unopenable log path
  stops startup with exit code `2` instead of running without logs.
- `docker-compose.yml` mounts a `correlator-logs` volume at
  `/var/log/opencanary-correlator` and points `OCC_LOG_FILE` at
  `/var/log/opencanary-correlator/logs/correlator.log`, so a file-based agent can
  collect the rotated log. The image ships that `logs/` directory owned by the
  runtime UID; Docker copies it into the volume with its ownership, so the
  unprivileged process can write without an init container. An empty
  `OCC_LOG_FILE` keeps stderr-only behaviour.
- Log records are flattened to one line, so a payload containing CRLF cannot
  forge an entry in the file a SIEM agent ingests.
- Per-channel alert detail: `OCC_TELEGRAM_DETAIL`, `OCC_SLACK_DETAIL`,
  `OCC_DISCORD_DETAIL`, `OCC_WEBHOOK_DETAIL` and `OCC_SMTP_DETAIL` accept
  `minimal`, `standard` or `detailed`. Chat channels default to `standard`;
  webhook and SMTP stay on `minimal` so SIEM parsers keep the legacy text.
- `connectors/dispatchers/alert_text.py` renders the multiline alert: the
  instance block (node name, host IP) first, then the attacker (IP and source
  port), the detection time and a log message summary. `detailed` adds the
  destination address, the event counter and more log entries.

### Changed

- Telegram sends the rendered layout with `parse_mode=MarkdownV2`, Slack with
  mrkdwn and Discord with markdown; every field is escaped for its channel and
  lines are separated with CRLF.
- Alert fields are sanitised before delivery: control characters are stripped,
  long values are clipped, and `logdata` keys that look like credentials
  (`PASSWORD`, `SECRET`, `TOKEN`, ...) are masked as `***`.

`minimal` stays byte-identical to 0.3.1 on every channel for messages that fit
the channel limit; a truncated message now ends with `…` instead of a hard cut.

### Fixed

- Bot and webhook secrets no longer reach the logs. `httpx` logs every request
  URL at `INFO`, and the Telegram Bot API only accepts the token as part of the
  path, so the token appeared in stderr and in the rotated log file. Log output
  is now redacted in the record and again at format time — covering tracebacks
  as well — masking `api.telegram.org/bot<token>`, Slack and Discord webhook
  paths, URL passwords, `?token=`/`?api_key=`-style query parameters and the
  configured endpoint URLs by exact value (the case of a token in the path of an
  arbitrary webhook host). The same filters cover the legacy console journal.
- Captured credentials are no longer logged. The SMB fallback branch logged the
  raw `logdata`, which can hold a password the canary captured; it now logs the
  incident key.
- Webhook, Slack and Discord URLs are hidden from `repr()` of the settings, and
  configuration errors name the list position and host instead of echoing the
  URL, so a bad entry cannot print its credential on startup.
- SMTP no longer drops an alert when a honeypot field contains CR/LF. Header
  values are flattened before rendering, and a rendering error is returned as a
  failed delivery instead of escaping `dispatch`, so the incident is audited and
  the remaining channels still receive it.

## [0.3.1] - 2026-10-26

Internal refactor. Behaviour, public interfaces, Redis key layout and audit
records are unchanged.

### Changed

- `incident.py` is split into `incident_model.py` (incident types) and
  `incident_report.py` (report building). Lua scripts moved to `storage/scripts.py`.
- Configuration validators moved from `config.py` into `config_validation.py`;
  `config.py` re-exports them, so existing imports keep working.
- TCP and syslog receivers share a base in `connectors/receivers/_base.py`.
- CLI dispatcher wiring uses one helper (`add_endpoints`); receiver arguments are shared.
- `docs/architecture.md` describes the new modules.

## [0.3.0] - 2026-10-25

Beta release. Production-readiness work: the public interfaces stay compatible
with `opencanaryd` (TCP JSON over `SocketHandler`, and syslog).

### Added

- Allowlist for the TCP and syslog receivers (`_allowlist.py`), with tests.
- `.gitattributes` for consistent line endings.
- Audit-event reference (`docs/audit-events.md`) now documents `alert_dispatch` outcomes for alerting.

### Changed

- Incident storage keeps a capped event list. Memory use stops growing once the
  cap is reached; the integration test checks this against a real Redis.
- Audit records always carry `timestamp`, `component`, `action`, `status` and
  `details`.
- README states that the health and `/metrics` ports must not be exposed publicly
  and that `/metrics` is not authenticated.

### Removed

- The legacy Python 2 tree (`opencanary_correlator/`, `bin/`, `setup.py`). The
  `legacy-py2` git tag keeps it in history.

### Security

- Telegram bot tokens are kept out of dispatch results, audit records and
  exception details; there is a test for this.
- Webhook, Slack and Discord URLs are validated in configuration: only http/https, and plain http only for loopback hosts.

## [0.2.0] - 2026-10-24

First release of the modernized fork. The Python 2 / Twisted correlator is
replaced by a stateless asyncio service, and `opencanaryd` nodes keep sending to
the same address without any change on the honeypot side.

### Added

- TCP JSON receiver for `SocketJSONHandler` traffic: newline-delimited UTF-8
  JSON on port `1514`, with `OCC_MAX_LINE_BYTES` (64 KiB), a partial-line
  timeout, `OCC_MAX_CONNECTIONS` and a bounded queue that applies backpressure
  instead of dropping events. Idle keep-alive sockets are left open.
- Syslog receiver (RFC 3164/5424, octet-counting or newline framing over TCP,
  `OCC_SYSLOG_UDP_ENABLED` for UDP). A plain-text body becomes a synthetic
  `LOG_BASE_MSG` event instead of being discarded.
- Pydantic v2 models for every event, keeping `src_host`, `src_port`,
  `dst_host`, `dst_port`, `logtype`, `node_id`, `local_time`, `utc_time`,
  `logdata` and unknown extra fields. Lenient on purpose: empty `src_host`, `-1`
  ports, hostnames, unknown `logtype` integers and unparsable timestamps are
  accepted rather than dropped.
- Stateless correlation in Redis: time windows, deduplication, incident locks
  and incident state, so replicas scale horizontally behind a load balancer.
  `OCC_EVENT_CONCURRENCY` shards events by source host into consumer lanes, so
  one slow host cannot stall the others.
- Dispatchers for Telegram, Slack, Discord, SMTP (`use_tls`) and generic SIEM
  webhooks, behind abstract receiver and dispatcher interfaces, each with a
  per-endpoint circuit breaker, a dispatch timeout and failure isolation.
- Operational surface: `GET /healthz` pings Redis before answering, Prometheus
  metrics on `/metrics`, and an audit log in strict JSON carrying `timestamp`,
  `component`, `action`, `status` and `details`.
- `--config` imports an existing legacy `opencanary_correlator.conf`, including
  per-incident horizons (`ftp.incident_horizon`, `smb.file_open_horizon`,
  `scans.*_horizon`, and the rest). Twilio and Mandrill keys are ignored with a
  log line, since SMS and the deprecated Mandrill SDK are not part of this
  release.
- Container image that runs as uid `10001` with a read-only root filesystem, and
  a `docker-compose.yml` for a correlator plus Redis.

### Changed

- Stored incident history is capped by `OCC_MAX_STORED_EVENTS` (default `100`):
  the timestamps and log entries kept per incident are bounded while
  `events_count` stays exact and the overflow is reported through
  `events_skipped` / `events_truncated`. The arrays previously grew without
  limit, which made a single hot incident quadratic to merge.
- Rate-limit windows are fixed rather than sliding, so a window resets on its
  boundary even under continuous traffic.
- Circuit breakers are per endpoint, not per channel type: one dead webhook no
  longer suppresses the healthy ones.

### Security

- Hostile payloads are rejected per line with an audit record instead of
  reaching the correlator: oversized lines, invalid UTF-8, non-JSON, `NaN` and
  infinity, excessive `logdata` nesting, and the `[ERR] '…'` line that
  `PyLogger.error()` emits when a canary fails internally.
- Every setting comes from the environment. `.env` is git-ignored and holds no
  committed secret; real deployments inject the variables from Docker secrets,
  a Kubernetes Secret or a systemd `EnvironmentFile`.
- Redis must be one logical server. Redis Cluster is unsupported because the
  incident write is a script over keys that hash to different slots; TLS
  (`rediss://`) and Unix sockets (`unix://`) are supported.
